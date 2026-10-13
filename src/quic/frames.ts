// QUIC frames (RFC 9000 §19): parse a decrypted packet payload into frames, and encode the
// ones we send (ACK, CRYPTO, STREAM, PADDING). Parsing must advance past EVERY frame type
// or the stream desyncs, so all variable layouts are decoded even when we ignore them.
import { readVarint, writeVarint } from './varint';
import { concat } from '../core/bytes';

export type Frame =
	| { type: 'padding' }
	| { type: 'ping' }
	| { type: 'ack'; largest: number }
	| { type: 'crypto'; offset: number; data: Uint8Array }
	| { type: 'stream'; id: number; offset: number; fin: boolean; data: Uint8Array }
	| { type: 'max_data' | 'max_stream_data' | 'max_streams' }
	| { type: 'new_connection_id' }
	| { type: 'handshake_done' }
	| { type: 'close'; app: boolean; code: number; reason: string }
	| { type: 'other' };

export function parseFrames(buf: Uint8Array): Frame[] {
	const out: Frame[] = [];
	let i = 0;
	const rv = () => {
		const r = readVarint(buf, i);
		i += r.len;
		return r.value;
	};
	while (i < buf.length) {
		const ft = rv();
		if (ft === 0x00) {
			while (i < buf.length && buf[i] === 0) i++;
			out.push({ type: 'padding' });
		} else if (ft === 0x01) out.push({ type: 'ping' });
		else if (ft === 0x02 || ft === 0x03) {
			const largest = rv();
			rv(); // ack_delay
			const rangeCount = rv();
			rv(); // first_range
			for (let k = 0; k < rangeCount; k++) {
				rv();
				rv();
			}
			if (ft === 0x03) {
				rv();
				rv();
				rv();
			} // ECN counts
			out.push({ type: 'ack', largest });
		} else if (ft === 0x04) {
			rv();
			rv();
			rv();
		} // RESET_STREAM
		else if (ft === 0x05) {
			rv();
			rv();
		} // STOP_SENDING
		else if (ft === 0x06) {
			const offset = rv();
			const len = rv();
			const data = buf.subarray(i, i + len);
			i += len;
			out.push({ type: 'crypto', offset, data });
		} else if (ft === 0x07) {
			const len = rv();
			i += len;
		} // NEW_TOKEN
		else if (ft >= 0x08 && ft <= 0x0f) {
			const id = rv();
			const offset = ft & 0x04 ? rv() : 0;
			const len = ft & 0x02 ? rv() : buf.length - i;
			const fin = !!(ft & 0x01);
			const data = buf.subarray(i, i + len);
			i += len;
			out.push({ type: 'stream', id, offset, fin, data });
		} else if (ft === 0x10) {
			rv();
			out.push({ type: 'max_data' });
		} else if (ft === 0x11) {
			rv();
			rv();
		} // MAX_STREAM_DATA
		else if (ft === 0x12 || ft === 0x13) {
			rv();
			out.push({ type: 'max_streams' });
		} else if (ft === 0x14) rv(); // DATA_BLOCKED
		else if (ft === 0x15) {
			rv();
			rv();
		} // STREAM_DATA_BLOCKED
		else if (ft === 0x16 || ft === 0x17) rv(); // STREAMS_BLOCKED
		else if (ft === 0x18) {
			rv(); // seq
			rv(); // retire
			const l = buf[i++]!;
			i += l + 16; // cid + stateless reset token
			out.push({ type: 'new_connection_id' });
		} else if (ft === 0x19) rv(); // RETIRE_CONNECTION_ID
		else if (ft === 0x1a || ft === 0x1b) i += 8; // PATH_CHALLENGE / RESPONSE
		else if (ft === 0x1c) {
			const code = rv();
			rv(); // frame type
			const rl = rv();
			const reason = Buffer.from(buf.subarray(i, i + rl)).toString('utf8');
			i += rl;
			out.push({ type: 'close', app: false, code, reason });
		} else if (ft === 0x1d) {
			const code = rv();
			const rl = rv();
			const reason = Buffer.from(buf.subarray(i, i + rl)).toString('utf8');
			i += rl;
			out.push({ type: 'close', app: true, code, reason });
		} else if (ft === 0x1e) out.push({ type: 'handshake_done' });
		else {
			out.push({ type: 'other' });
			break; // unknown frame — stop to avoid desync
		}
	}
	return out;
}

/** CRYPTO frame. */
export const cryptoFrame = (offset: number, data: Uint8Array): Uint8Array => concat(Uint8Array.of(0x06), writeVarint(offset), writeVarint(data.length), data);

/** STREAM frame with offset + length + optional FIN (types 0x0a/0x0b base 0x08|OFF|LEN[|FIN]). */
export function streamFrame(id: number, offset: number, data: Uint8Array, fin: boolean): Uint8Array {
	const type = 0x08 | 0x04 | 0x02 | (fin ? 0x01 : 0); // OFF + LEN + FIN?
	return concat(writeVarint(type), writeVarint(id), writeVarint(offset), writeVarint(data.length), data);
}

/** Packet numbers received in one number space, as disjoint [lo, hi] ranges, highest first.
 *  ACKs must name exactly these: acknowledging a packet that never arrived tells the peer not
 *  to resend it, leaving a permanent hole in the stream. */
export class PnRanges {
	private r: [number, number][] = [];
	private static readonly MAX = 64; // older ranges are forgotten (and no longer acked)

	get largest(): number {
		return this.r.length ? this.r[0]![1] : -1;
	}

	/** Record `pn`; false when it was already received (a duplicate to ignore). */
	add(pn: number): boolean {
		const r = this.r;
		let i = 0;
		while (i < r.length && r[i]![0] > pn) i++; // first range whose lo ≤ pn
		if (i < r.length && r[i]![1] >= pn) return false; // inside an existing range
		const joinsAbove = i > 0 && r[i - 1]![0] === pn + 1;
		const joinsBelow = i < r.length && r[i]![1] === pn - 1;
		if (joinsAbove && joinsBelow) {
			r[i - 1]![0] = r[i]![0];
			r.splice(i, 1);
		} else if (joinsAbove) r[i - 1]![0] = pn;
		else if (joinsBelow) r[i]![1] = pn;
		else {
			r.splice(i, 0, [pn, pn]);
			if (r.length > PnRanges.MAX) r.pop();
		}
		return true;
	}

	/** ACK frame (RFC 9000 §19.3) for exactly the received packets. */
	ackFrame(delay = 0): Uint8Array {
		const r = this.r;
		const parts: Uint8Array[] = [Uint8Array.of(0x02), writeVarint(r[0]![1]), writeVarint(delay), writeVarint(r.length - 1), writeVarint(r[0]![1] - r[0]![0])];
		for (let k = 1; k < r.length; k++) parts.push(writeVarint(r[k - 1]![0] - r[k]![1] - 2), writeVarint(r[k]![1] - r[k]![0])); // gap, range length
		return concat(...parts);
	}
}

/** Reorders STREAM / CRYPTO data into contiguous bytes. Tolerates duplicates and data resent
 *  cut at different boundaries — a retransmission rarely matches the original frame's
 *  offsets, so waiting for a frame that starts exactly at `consumed` can stall forever. */
export class Reassembler {
	consumed = 0;
	private pending = new Map<number, Uint8Array>();

	push(offset: number, data: Uint8Array): void {
		if (!data.length || offset + data.length <= this.consumed) return; // nothing new
		const have = this.pending.get(offset);
		if (!have || have.length < data.length) this.pending.set(offset, data);
	}

	/** Every byte now contiguous from `consumed` (advancing it); empty when none. */
	take(): Uint8Array {
		const parts: Uint8Array[] = [];
		for (let progressed = true; progressed && this.pending.size; ) {
			progressed = false;
			for (const [off, data] of this.pending) {
				const end = off + data.length;
				if (end <= this.consumed) this.pending.delete(off);
				else if (off <= this.consumed) {
					parts.push(data.subarray(this.consumed - off));
					this.consumed = end;
					this.pending.delete(off);
					progressed = true;
				}
			}
		}
		return parts.length === 1 ? parts[0]! : concat(...parts);
	}
}

/** MAX_DATA: connection-level flow-control credit. */
export const maxDataFrame = (max: number): Uint8Array => concat(Uint8Array.of(0x10), writeVarint(max));
/** MAX_STREAM_DATA: flow-control credit for one stream. */
export const maxStreamDataFrame = (id: number, max: number): Uint8Array => concat(Uint8Array.of(0x11), writeVarint(id), writeVarint(max));

export const pingFrame = (): Uint8Array => Uint8Array.of(0x01);

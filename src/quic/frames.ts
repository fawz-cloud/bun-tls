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

/** ACK frame acknowledging 0..largest contiguously (one range). */
export function ackFrame(largest: number, delay = 0): Uint8Array {
	return concat(Uint8Array.of(0x02), writeVarint(largest), writeVarint(delay), writeVarint(0), writeVarint(largest));
}

export const pingFrame = (): Uint8Array => Uint8Array.of(0x01);

// TLS 1.3 session tickets for resumption + 0-RTT (RFC 8446 §4.6.1). A ticket is
// captured from a server NewSessionTicket; a later handshake can present it as a
// pre_shared_key to skip the full handshake, and (if the server allows early data)
// send the request as 0-RTT. Tickets are single-use.
import type { HashAlg } from '../core/crypto';

export interface Ticket {
	identity: Uint8Array; // the opaque ticket, echoed in pre_shared_key.identities
	psk: Uint8Array; // resumption PSK derived for this ticket
	hash: HashAlg; // the PSK is bound to this suite's hash
	cipher: number; // cipher suite the ticket was issued under
	ageAdd: number; // ticket_age_add (u32) — obfuscates the reported age
	obtainedAt: number; // epoch ms the ticket was received
	lifetime: number; // ticket_lifetime (seconds)
	maxEarlyData: number; // max_early_data_size (0 = no 0-RTT allowed)
	alpn: string | null;
}

/** Per-host ticket cache. Newest first; single-use (taken on use). */
export class TicketStore {
	private byHost = new Map<string, Ticket[]>();

	add(host: string, t: Ticket): void {
		const list = this.byHost.get(host) ?? [];
		list.unshift(t);
		if (list.length > 4) list.length = 4; // keep a few fresh ones, drop the rest
		this.byHost.set(host, list);
	}

	/** Take one unexpired ticket for host (removes it — tickets are single-use). */
	take(host: string): Ticket | null {
		const list = this.byHost.get(host);
		if (!list) return null;
		const now = Date.now();
		while (list.length) {
			const t = list.shift()!;
			if (now - t.obtainedAt < t.lifetime * 1000) return t;
		}
		return null;
	}
}

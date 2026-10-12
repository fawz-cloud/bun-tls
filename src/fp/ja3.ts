// fromJa3("771,4865-...,0-23-...,29-23-24,0") → Fingerprint. Impersonate a target
// from a single JA3 string (like curl_cffi ja3=), LLM-friendly.
// Note: JA3 drops GREASE and doesn't fully capture extension order — the result
// is close, not a guaranteed byte-identical JA4. To match exactly, capture the
// real extension order instead.
import type { Fingerprint } from '../tls/clienthello';
import type { Extension } from '../tls/extensions';
import * as E from '../tls/extensions';
import { Ext, Group, SigAlg } from '../core/consts';

/** Default sigalgs (not present in JA3) — used when the fingerprint needs ext 13. */
export const DEFAULT_SIGALGS = [
	SigAlg.ecdsa_secp256r1_sha256,
	SigAlg.rsa_pss_rsae_sha256,
	SigAlg.rsa_pkcs1_sha256,
	SigAlg.ecdsa_secp384r1_sha384,
	SigAlg.rsa_pss_rsae_sha384,
	SigAlg.rsa_pkcs1_sha384,
	SigAlg.rsa_pss_rsae_sha512,
	SigAlg.rsa_pkcs1_sha512
];

const SUPPORTED_KS = new Set<number>([Group.x25519, Group.secp256r1, Group.secp384r1]);

export interface FromJa3Opts {
	alpn?: string[];
	sigAlgs?: number[];
	/** key_share groups (default: first JA3 curve we support). */
	keyShareGroups?: number[];
	/** Inject GREASE like Chrome (hashes unchanged, bytes closer to real). */
	grease?: boolean;
}

export function fromJa3(ja3: string, opts: FromJa3Opts = {}): Fingerprint {
	const [, ciphersF, extsF, curvesF, ecpfF] = ja3.split(',');
	const nums = (s?: string) => (s ? s.split('-').filter(Boolean).map(Number) : []);
	const ciphers = nums(ciphersF);
	const extTypes = nums(extsF);
	const curves = nums(curvesF);
	const ecpf = nums(ecpfF);
	const sigAlgs = opts.sigAlgs ?? DEFAULT_SIGALGS;
	const alpn = opts.alpn ?? ['http/1.1'];

	const builder = (type: number): Extension => {
		switch (type) {
			case Ext.server_name: return E.serverName();
			case Ext.status_request: return E.statusRequest();
			case Ext.supported_groups: return E.supportedGroups(curves.length ? curves : [Group.x25519]);
			case Ext.ec_point_formats: return E.ecPointFormats(ecpf.length ? ecpf : [0]);
			case Ext.signature_algorithms: return E.signatureAlgorithms(sigAlgs);
			case Ext.alpn: return E.alpn(alpn);
			case Ext.extended_master_secret: return E.extendedMasterSecret();
			case Ext.compress_certificate: return E.compressCertificate([2]);
			case Ext.session_ticket: return E.sessionTicket();
			case Ext.supported_versions: return E.supportedVersions();
			case Ext.psk_key_exchange_modes: return E.pskKeyExchangeModes([1]);
			case Ext.key_share: return E.keyShare();
			case Ext.renegotiation_info: return E.renegotiationInfo();
			default: return E.grease(type); // unknown ext: empty body
		}
	};

	// key_share: supported groups from JA3 (default x25519).
	const ks = opts.keyShareGroups ?? curves.filter((g) => SUPPORTED_KS.has(g)).slice(0, 1);
	return {
		ciphers,
		keyShareGroups: ks.length ? ks : [Group.x25519],
		extensions: extTypes.map(builder),
		grease: opts.grease
	};
}

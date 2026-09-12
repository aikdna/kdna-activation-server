// Synthetic container writer used only by tests. Runtime parsing belongs to Core.
import { encode } from 'cbor-x';
export const tuple = Object.freeze({ container: '0.2.0', payload_profile: 'kdna.payload.judgment',
  payload_version: '0.2.0', core: 'kdna.core/0.3.0', ir: 'kdna.canonical-ir/0.2.0',
  runtime: 'kdna.runtime-capsule/0.2.0', plan: 'kdna.consumption-plan/0.2.0',
  host: 'kdna.agent-host/0.2.0', trace: 'kdna.judgment-trace/0.2.0', read: 'kdna.read/0.2.0' });
export const asset = Object.freeze({ asset_id: 'asset:reference-host', asset_version: '1.0.0', judgment_version: '1.0.0' });
export function readRequest(overrides = {}) {
  return { request_id: 'request:reference', tuple, budget_bytes: 1000000, mode: 'exact_selection',
    selection: { asset_id: asset.asset_id, asset_version: asset.asset_version, judgment_id: 'judgment:0' },
    handle: null, ...overrides };
}
function crc32(bytes) {
  let crc = 0xffffffff;
  for (const b of bytes) { crc ^= b; for (let i = 0; i < 8; i++) crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1; }
  return (crc ^ 0xffffffff) >>> 0;
}
export function zip(entries) {
  const local = [], central = [];
  let offset = 0;
  for (const [name, value] of entries) {
    const bytes = Buffer.from(value), filename = Buffer.from(name), crc = crc32(bytes);
    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50); head.writeUInt16LE(20, 4); head.writeUInt32LE(crc, 14);
    head.writeUInt32LE(bytes.length, 18); head.writeUInt32LE(bytes.length, 22); head.writeUInt16LE(filename.length, 26);
    const directory = Buffer.alloc(46);
    directory.writeUInt32LE(0x02014b50); directory.writeUInt16LE(20, 4); directory.writeUInt16LE(20, 6);
    directory.writeUInt32LE(crc, 16); directory.writeUInt32LE(bytes.length, 20); directory.writeUInt32LE(bytes.length, 24);
    directory.writeUInt16LE(filename.length, 28); directory.writeUInt32LE(offset, 42);
    local.push(head, filename, bytes); central.push(directory, filename); offset += head.length + filename.length + bytes.length;
  }
  const table = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(table.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, table, end]);
}
export function payloadFor(count = 1) {
  const judgments = Array.from({ length: count }, (_, i) => ({
    id: `judgment:${i}`, label: `Unit ${i}`, focus: `Focus ${i}`,
    subject: { actor_ids: ['actor:author'], statement: 'A synthetic subject' },
    scope: { statement: 'Synthetic integration scope' },
    result_contract: { id: `contract:${i}`, form: { term: 'result.form.assertion' },
      shape: { kind: 'scalar', scalar_type: 'text' }, minimum: 1, maximum: 1,
      allowed_result_types: [{ term: 'result.type.text' }] },
    result: { contract_ref: `contract:${i}`, result_type: { term: 'result.type.text' },
      value: { kind: 'text', value: `RESULT_SENTINEL_${i}` } },
  }));
  return { profile: 'kdna.payload.judgment', profile_version: '0.2.0', asset,
    actors: [{ id: 'actor:author', kind: 'person', name: 'Synthetic author' }],
    scope: { statement: 'Only the reference Host conformance fixture' }, judgments };
}
export function fixture(count = 1, mutate = () => {}, entries = []) {
  const payload = payloadFor(count);
  mutate(payload);
  const manifest = { format_version: '0.2.0', asset_id: asset.asset_id, asset_uid: 'asset:reference-uid',
    asset_type: 'fixture', title: 'Reference Host synthetic fixture', version: '1.0.0', judgment_version: '1.0.0',
    created_at: '2026-09-06T00:00:00Z', updated_at: '2026-09-06T00:00:00Z',
    compatibility: { min_loader_version: '0.24.0-rc.component-semantics.2', profile: 'kdna.payload.judgment', profile_version: '0.2.0' },
    payload: { path: 'payload.kdnab', encoding: 'cbor', encrypted: false },
    runtime: { mandatory_entries: ['payload.kdnab'] }, access: 'public' };
  return zip([['mimetype', 'application/vnd.kdna.asset'], ['kdna.json', JSON.stringify(manifest)],
    ['payload.kdnab', encode(payload)], ...entries]);
}
export function allowAll({ snapshot }) {
  return { decision: 'allow', scope: snapshot.ir.nodes.map(node => node.id), epoch: 'epoch:1', policyId: 'policy:synthetic' };
}
export function upload(operation, bytes, candidate = readRequest()) {
  const form = new FormData();
  form.set('file', new Blob([bytes]), 'synthetic.kdna');
  if (operation !== 'validate') form.set('request', JSON.stringify(candidate));
  return new Request(`http://localhost/api/kdna/${operation}`, { method: 'POST', body: form });
}

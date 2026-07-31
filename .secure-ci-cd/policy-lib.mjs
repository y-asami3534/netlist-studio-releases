import { createHash } from "node:crypto";
import { lstat, open, readdir, readFile, realpath } from "node:fs/promises";
import path from "node:path";

export const FULL_SHA = /^[0-9a-f]{40}$/u;
export const OBJECT_ID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
export const SHA256 = /^[0-9a-f]{64}$/u;
export const SHA512 = /^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==$/u;
export const STABLE_SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u;
const UTC_SECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;

export class PolicyViolation extends Error {
  constructor(message) {
    super(message);
    this.name = "PolicyViolation";
    this.exitCode = 1;
  }
}

export class EvidenceUnavailable extends Error {
  constructor(message) {
    super(message);
    this.name = "EvidenceUnavailable";
    this.exitCode = 2;
  }
}

export class UsageError extends Error {
  constructor(message) {
    super(message);
    this.name = "UsageError";
    this.exitCode = 2;
  }
}

export function safeErrorMessage(error) {
  return error instanceof Error ? `${error.name}: ${error.message}` : "Unknown error";
}

function skipWhitespace(state) {
  while (state.index < state.text.length && /\s/u.test(state.text[state.index])) {
    state.index += 1;
  }
}

function parseString(state) {
  const start = state.index;
  state.index += 1;
  while (state.index < state.text.length) {
    const character = state.text[state.index];
    if (character === '"') {
      state.index += 1;
      try {
        return JSON.parse(state.text.slice(start, state.index));
      } catch {
        throw new UsageError("invalid JSON string");
      }
    }
    if (character === "\\") state.index += 2;
    else {
      if (character.charCodeAt(0) < 0x20) throw new UsageError("JSON control character");
      state.index += 1;
    }
  }
  throw new UsageError("unterminated JSON string");
}

function parseValue(state, depth) {
  if (depth > 64) throw new UsageError("JSON nesting exceeds 64");
  skipWhitespace(state);
  const character = state.text[state.index];
  if (character === "{") {
    state.index += 1;
    const keys = new Set();
    skipWhitespace(state);
    if (state.text[state.index] === "}") {
      state.index += 1;
      return;
    }
    while (state.index < state.text.length) {
      if (state.text[state.index] !== '"') throw new UsageError("JSON key must be a string");
      const key = parseString(state);
      if (keys.has(key)) throw new UsageError(`duplicate JSON key: ${key}`);
      keys.add(key);
      skipWhitespace(state);
      if (state.text[state.index] !== ":") throw new UsageError("missing JSON colon");
      state.index += 1;
      parseValue(state, depth + 1);
      skipWhitespace(state);
      if (state.text[state.index] === "}") {
        state.index += 1;
        return;
      }
      if (state.text[state.index] !== ",") throw new UsageError("missing JSON comma");
      state.index += 1;
      skipWhitespace(state);
    }
    throw new UsageError("unterminated JSON object");
  }
  if (character === "[") {
    state.index += 1;
    skipWhitespace(state);
    if (state.text[state.index] === "]") {
      state.index += 1;
      return;
    }
    while (state.index < state.text.length) {
      parseValue(state, depth + 1);
      skipWhitespace(state);
      if (state.text[state.index] === "]") {
        state.index += 1;
        return;
      }
      if (state.text[state.index] !== ",") throw new UsageError("missing JSON array comma");
      state.index += 1;
      skipWhitespace(state);
    }
    throw new UsageError("unterminated JSON array");
  }
  if (character === '"') {
    parseString(state);
    return;
  }
  const primitive = state.text.slice(state.index).match(
    /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/u
  )?.[0];
  if (!primitive) throw new UsageError("invalid JSON value");
  state.index += primitive.length;
}

export function parseJsonStrict(text, maximumBytes = 1024 * 1024) {
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > maximumBytes) {
    throw new UsageError(`JSON input exceeds ${maximumBytes} bytes`);
  }
  if (text.charCodeAt(0) === 0xfeff) throw new UsageError("JSON must not contain a BOM");
  const state = { text, index: 0 };
  parseValue(state, 0);
  skipWhitespace(state);
  if (state.index !== text.length) throw new UsageError("data follows JSON document");
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new UsageError(`invalid JSON: ${error.message}`);
  }
}

export function canonicalJson(value) {
  const normalize = (input) => {
    if (Array.isArray(input)) return input.map(normalize);
    if (input && typeof input === "object") {
      return Object.fromEntries(Object.keys(input).sort().map((key) => [key, normalize(input[key])]));
    }
    return input;
  };
  return `${JSON.stringify(normalize(value), null, 2)}\n`;
}

export function sha256Text(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, expected, label) {
  if (!isRecord(value)) throw new PolicyViolation(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (actual.join("\0") !== canonical.join("\0")) {
    throw new PolicyViolation(`${label} keys must be exactly: ${canonical.join(", ")}`);
  }
  return value;
}

function positiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new PolicyViolation(`${label} must be positive`);
  return value;
}

function requireString(value, expected, label) {
  if (value !== expected) throw new PolicyViolation(`${label} must be ${expected}`);
}

function requirePattern(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new PolicyViolation(`${label} is invalid`);
  }
  return value;
}

export async function readRegularText(filePath, maximumBytes = 1024 * 1024) {
  const metadata = await lstat(filePath).catch(() => null);
  if (!metadata?.isFile() || metadata.isSymbolicLink() || metadata.size > maximumBytes) {
    throw new UsageError(`expected bounded regular file: ${filePath}`);
  }
  const text = await readFile(filePath, "utf8");
  if (Buffer.byteLength(text, "utf8") !== metadata.size || text.charCodeAt(0) === 0xfeff) {
    throw new UsageError(`file bytes are not canonical UTF-8: ${filePath}`);
  }
  return text;
}

export async function readCanonicalJson(filePath) {
  const text = await readRegularText(filePath);
  const value = parseJsonStrict(text);
  if (text !== canonicalJson(value)) throw new PolicyViolation(`${path.basename(filePath)} is not canonical JSON`);
  return { text, value };
}

function parsePermissionBlock(lines, index, indentation) {
  const declaration = lines[index].slice(indentation).match(/^permissions:\s*(.*?)\s*$/u);
  if (!declaration) throw new PolicyViolation("workflow permissions declaration is invalid");
  if (declaration[1] === "{}") return { permissions: {}, nextIndex: index + 1 };
  if (declaration[1] !== "") throw new PolicyViolation("workflow permissions must use an explicit block");
  const permissions = {};
  let nextIndex = index + 1;
  for (; nextIndex < lines.length; nextIndex += 1) {
    const line = lines[nextIndex];
    if (/^\s*(?:#.*)?$/u.test(line)) continue;
    const leading = line.match(/^\s*/u)[0].length;
    if (leading <= indentation) break;
    const entry = line.match(new RegExp(`^\\s{${indentation + 2}}([a-z-]+):\\s*(read|write|none)\\s*$`, "u"));
    if (!entry || Object.hasOwn(permissions, entry[1])) throw new PolicyViolation("workflow permissions block is invalid");
    permissions[entry[1]] = entry[2];
  }
  return { permissions, nextIndex };
}

function trustedJobPermissions(text) {
  const lines = text.split("\n");
  const blocks = new Map();
  let currentJob = null;
  let inJobs = false;
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (/^jobs:\s*$/u.test(line)) {
      inJobs = true;
      continue;
    }
    if (inJobs && /^\S/u.test(line)) {
      inJobs = false;
      currentJob = null;
    }
    const job = inJobs ? line.match(/^  ([a-z0-9-]+):\s*$/u) : null;
    if (job) currentJob = job[1];
    const indentation = line.match(/^\s*/u)[0].length;
    if (!/^\s*permissions:/u.test(line)) continue;
    const scope = indentation === 0 ? "workflow" : indentation === 4 && currentJob ? currentJob : null;
    if (!scope || blocks.has(scope)) throw new PolicyViolation("workflow permissions scope is invalid or duplicated");
    const block = parsePermissionBlock(lines, index, indentation);
    blocks.set(scope, block.permissions);
    index = block.nextIndex - 1;
  }
  return blocks;
}

function exactPermissionMap(actual, expected, label) {
  if (canonicalJson(actual) !== canonicalJson(expected)) throw new PolicyViolation(`${label} permissions are not least-privilege`);
}

export function validateWorkflowText(text, role, contract) {
  const forbidden = [
    /\bpaths-ignore\s*:/u,
    /\bpaths\s*:/u,
    /\bcontinue-on-error\s*:/u,
    /\bsecrets\s*\./u,
    /permissions\s*:\s*(?:read-all|write-all)/u,
    /github\.head_ref/u,
    /^\s*(?:npm|npx|pnpm|yarn|bun)\b/gmu,
    /^\s*eval\b/gmu,
  ];
  for (const pattern of forbidden) if (pattern.test(text)) throw new PolicyViolation(`${role} workflow contains forbidden construct: ${pattern}`);
  const uses = [...text.matchAll(/^\s*uses:\s*([^\s#]+)\s*$/gmu)].map((match) => match[1]);
  const allowedActions = new Set(Object.values(contract.toolchain.actions).map((action) => `${action.repository}@${action.commitSha}`));
  for (const action of uses) if (!allowedActions.has(action)) throw new PolicyViolation(`${role} workflow uses an unpinned or unknown action: ${action}`);
  if (uses.some((action) => !/@[0-9a-f]{40}$/u.test(action))) throw new PolicyViolation(`${role} workflow action is not full-SHA pinned`);
  const checkout = `${contract.toolchain.actions.checkout.repository}@${contract.toolchain.actions.checkout.commitSha}`;
  const checkoutCount = uses.filter((action) => action === checkout).length;
  const refs = [...text.matchAll(/^\s+ref:\s*(.+?)\s*$/gmu)].map((match) => match[1]);
  const credentialGuards = [...text.matchAll(/^\s+persist-credentials:\s*false\s*$/gmu)].length;
  if (checkoutCount === 0 || refs.length !== checkoutCount || credentialGuards !== checkoutCount) throw new PolicyViolation(`${role} workflow checkout must be explicit and credentialless`);
  const pullRequestBaseRef = "${{ github.event.pull_request.base.sha }}";
  const defaultBranchRef = "${{ github.event.repository.default_branch }}";
  const expectedRef = role === "manual-promotion" ? defaultBranchRef : pullRequestBaseRef;
  if (refs.some((ref) => ref !== expectedRef)) throw new PolicyViolation(`${role} workflow may check out only its trusted policy ref`);
  const conditions = [...text.matchAll(/^\s+if:\s*(.+?)\s*$/gmu)].map((match) => match[1]);
  if (role === "trusted-policy") {
    if (conditions.length !== 1 || conditions[0] !== "${{ always() }}") throw new PolicyViolation("trusted workflow may use only the final fail-closed condition");
  } else if (conditions.length !== 0) {
    throw new PolicyViolation(`${role} workflow must not contain conditional jobs or steps`);
  }
  if (role === "source-ci") {
    for (const token of ["pull_request:", "channel-data:", "name: channel-data", "validate-change", "--github", "write-source-evidence", "contents: read"]) if (!text.includes(token)) throw new PolicyViolation(`source workflow is missing ${token}`);
    if (text.includes("pull_request_target:") || text.includes("statuses: write")) throw new PolicyViolation("source workflow trust boundary is invalid");
  }
  if (role === "trusted-policy") {
    for (const token of ["pull_request_target:", "initialize-trusted-status:", "validate-candidate-data:", "publish-trusted-status:", "--state pending", "--context trusted-policy", "statuses: write"]) if (!text.includes(token)) throw new PolicyViolation(`trusted workflow is missing ${token}`);
    if (text.includes("upload-artifact@") || text.includes("workflow_dispatch:") || text.includes("set-status") || text.includes("verify-trusted-publication")) throw new PolicyViolation("trusted workflow contains a split or unsafe status publication path");
    if ((text.match(/policy-cli\.mjs publish-trusted-status/gu) ?? []).length !== 2) throw new PolicyViolation("trusted workflow must publish both status transitions exactly once");
    const blocks = trustedJobPermissions(text);
    if ([...blocks.keys()].sort().join("\0") !== ["initialize-trusted-status", "publish-trusted-status", "validate-candidate-data", "workflow"].sort().join("\0")) throw new PolicyViolation("trusted workflow permission scopes are incomplete");
    exactPermissionMap(blocks.get("workflow"), {}, "trusted workflow");
    const publisher = { actions: "read", contents: "read", "pull-requests": "read", statuses: "write" };
    exactPermissionMap(blocks.get("initialize-trusted-status"), publisher, "trusted initializer");
    exactPermissionMap(blocks.get("validate-candidate-data"), { contents: "read" }, "trusted validator");
    exactPermissionMap(blocks.get("publish-trusted-status"), publisher, "trusted publisher");
  }
  if (role === "manual-promotion") {
    for (const token of ["workflow_dispatch:", "verify-promotion:", "verify-run-evidence", "write-promotion-receipt", "actions: read", "contents: read"]) if (!text.includes(token)) throw new PolicyViolation(`promotion workflow is missing ${token}`);
    if (text.includes("set-status") || text.includes("publish-trusted-status") || text.includes("pull_request_target:")) throw new PolicyViolation("promotion workflow must remain read-only");
  }
}

export function validateConfiguration(contract, policy) {
  exactKeys(contract, ["canonical", "externalHolds", "kind", "promotion", "provider", "providerInvariants", "requiredChecks", "schemaVersion", "toolchain", "trustZones"], "contract");
  if (contract.kind !== "netlist-studio-release-channel-pipeline" || contract.schemaVersion !== 1 || contract.provider !== "github") {
    throw new PolicyViolation("unsupported pipeline contract");
  }
  const repository = exactKeys(contract.canonical?.repository, ["branch", "fullName", "id", "ownerType"], "contract.canonical.repository");
  if (repository.id !== 1280945456 || repository.fullName !== "y-asami3534/netlist-studio-releases" || repository.branch !== "main" || repository.ownerType !== "User") {
    throw new PolicyViolation("canonical repository identity drifted");
  }
  const source = contract.trustZones?.["source-ci"];
  const trusted = contract.trustZones?.["trusted-policy"];
  const promotion = contract.trustZones?.["manual-promotion"];
  if (source?.event !== "pull_request" || source.executesCandidate !== false || source.candidateMode !== "git-data-only" || source.allowSecrets !== false || source.workflowPath !== ".github/workflows/channel-source-ci.yml") {
    throw new PolicyViolation("source CI must be candidate-data-only and unprivileged");
  }
  if (trusted?.event !== "pull_request_target" || trusted.executesCandidate !== false || trusted.candidateMode !== "git-data-only" || trusted.policySource !== "pull-request-base" || trusted.workflowPath !== ".github/workflows/channel-trusted-policy.yml") {
    throw new PolicyViolation("trusted policy boundary is invalid");
  }
  if (promotion?.event !== "workflow_dispatch" || promotion.externalMutation !== false || promotion.candidateMode !== "git-data-only" || promotion.allowSecrets !== false || promotion.workflowPath !== ".github/workflows/channel-promotion-evidence.yml") throw new PolicyViolation("promotion evidence boundary is invalid");
  const contexts = contract.requiredChecks.map((check) => check.name);
  if (contexts.join("\0") !== "channel-data\0trusted-policy") throw new PolicyViolation("required check set drifted");
  const gate = contract.providerInvariants?.requiredWorkflowGate;
  if (gate?.mode !== "approved-personal-repository-exception" || gate.required !== false || gate.allowBypass !== false || gate.exceptionId !== "personal-repository-no-required-workflow-v1") {
    throw new PolicyViolation("personal repository exception is not explicit");
  }
  if (contract.providerInvariants.readbackRequired !== true || contract.providerInvariants.strictRequiredChecks !== true || contract.providerInvariants.requireCurrentBaseForMerge !== true) {
    throw new PolicyViolation("provider read-back and strict checks are required");
  }
  const actions = exactKeys(contract.toolchain?.actions, ["checkout", "setupNode", "uploadArtifact"], "contract toolchain actions");
  const actionRepositories = { checkout: "actions/checkout", setupNode: "actions/setup-node", uploadArtifact: "actions/upload-artifact" };
  for (const [name, action] of Object.entries(actions)) {
    exactKeys(action, ["commitSha", "repository", "version"], `contract action ${name}`);
    if (action.repository !== actionRepositories[name]) throw new PolicyViolation(`contract action repository drifted: ${name}`);
    if (!FULL_SHA.test(action?.commitSha ?? "")) throw new PolicyViolation("actions must use full commit SHAs");
  }

  exactKeys(policy, ["bootstrap", "channel", "changeClasses", "limits", "providerException", "repositories", "releaseTag", "schema", "schemaVersion"], "channel policy");
  if (policy.schema !== "netlist-studio.stable-channel-policy" || policy.schemaVersion !== 1) throw new PolicyViolation("unsupported channel policy");
  if (policy.repositories.release.id !== repository.id || policy.repositories.release.fullName !== repository.fullName || policy.repositories.source.id !== 1314731557 || policy.repositories.source.fullName !== "y-asami3534/netlist-studio") {
    throw new PolicyViolation("channel repository identity drifted");
  }
  if (policy.bootstrap.baseCommit !== "db9a9a6166b5b94043a930bbc73633b27dc42b8f" || policy.bootstrap.oneTime !== true) throw new PolicyViolation("bootstrap exception drifted");
  exactKeys(policy.changeClasses, ["policy-maintenance", "provider-policy", "release-manifest", "stable-channel"], "channel policy change classes");
  for (const [className, paths] of Object.entries(policy.changeClasses)) {
    if (!Array.isArray(paths) || paths.length === 0 || new Set(paths).size !== paths.length || paths.some((relativePath) => typeof relativePath !== "string" || relativePath.length === 0)) throw new PolicyViolation(`channel policy change class is invalid: ${className}`);
  }
  if (!exactPathSet(policy.changeClasses["policy-maintenance"], policy.bootstrap.requiredPaths)) throw new PolicyViolation("policy maintenance path set must match the protected bootstrap path set");
  if (policy.providerException.approved !== true || policy.providerException.exceptionId !== gate.exceptionId) throw new PolicyViolation("provider exception is not approved and bound");
  if (policy.channel.directory !== "channels/stable/macos/arm64" || policy.channel.initialVersion !== "0.40.0" || policy.channel.initialPreviousVersion !== "0.39.23") throw new PolicyViolation("stable channel identity drifted");
  return Object.freeze({ contract, policy });
}

export function allowedRepositoryPaths(policy) {
  return new Set([
    ...policy.bootstrap.requiredPaths,
    ...Object.values(policy.changeClasses).flat(),
  ]);
}

export async function readRepositorySnapshot(root, policy) {
  const requested = path.resolve(root);
  const rootMetadata = await lstat(requested).catch(() => null);
  if (!rootMetadata?.isDirectory() || rootMetadata.isSymbolicLink()) throw new UsageError("snapshot root must be a real directory");
  const canonicalRoot = await realpath(requested);
  const files = new Map();
  let totalBytes = 0;
  async function visit(directory, relative = "") {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (!relative && entry.name === ".git") continue;
      const relativePath = relative ? `${relative}/${entry.name}` : entry.name;
      const absolutePath = path.join(directory, entry.name);
      const metadata = await lstat(absolutePath);
      if (metadata.isSymbolicLink()) throw new PolicyViolation(`symlink is forbidden: ${relativePath}`);
      if (entry.isDirectory()) {
        await visit(absolutePath, relativePath);
        continue;
      }
      if (!entry.isFile() || (metadata.mode & 0o111) !== 0) throw new PolicyViolation(`non-regular or executable entry is forbidden: ${relativePath}`);
      if (metadata.size > policy.limits.maximumFileBytes) throw new PolicyViolation(`file is oversized: ${relativePath}`);
      totalBytes += metadata.size;
      if (totalBytes > policy.limits.maximumRepositoryBytes) throw new PolicyViolation("repository snapshot is oversized");
      files.set(relativePath, await readFile(absolutePath));
      if (files.size > policy.limits.maximumTreeEntries) throw new PolicyViolation("repository tree has too many entries");
    }
  }
  await visit(canonicalRoot);
  const allowed = allowedRepositoryPaths(policy);
  for (const relativePath of files.keys()) {
    if (!allowed.has(relativePath)) throw new PolicyViolation(`unexpected repository path: ${relativePath}`);
  }
  return Object.freeze({ root: canonicalRoot, files });
}

export function changedPaths(base, candidate) {
  const all = new Set([...base.files.keys(), ...candidate.files.keys()]);
  return [...all].filter((relativePath) => {
    const left = base.files.get(relativePath);
    const right = candidate.files.get(relativePath);
    return !left || !right || !left.equals(right);
  }).sort();
}

function exactPathSet(actual, expected) {
  return actual.join("\0") === [...expected].sort().join("\0");
}

export function classifyChangedPaths(paths, { baseHasPolicy, baseSha, policy }) {
  if (!Array.isArray(paths) || paths.length === 0) throw new PolicyViolation("candidate has no changes");
  const changed = [...paths].sort();
  const bootstrap = [...policy.bootstrap.requiredPaths].sort();
  if (!baseHasPolicy) {
    if (baseSha !== policy.bootstrap.baseCommit) throw new PolicyViolation("bootstrap base commit is not exact");
    if (!exactPathSet(changed, bootstrap)) throw new PolicyViolation("bootstrap must change the exact protected path set");
    return "policy-bootstrap";
  }
  for (const className of ["provider-policy", "release-manifest", "stable-channel"]) {
    if (exactPathSet(changed, policy.changeClasses[className])) return className;
  }
  const maintenance = new Set(policy.changeClasses["policy-maintenance"] ?? []);
  if (changed.every((relativePath) => maintenance.has(relativePath))) return "policy-maintenance";
  throw new PolicyViolation("change classes must not be mixed or incomplete");
}

function versionParts(value, label) {
  const match = typeof value === "string" ? value.match(STABLE_SEMVER) : null;
  if (!match) throw new PolicyViolation(`${label} must be stable SemVer`);
  return match.slice(1).map(Number);
}

export function compareVersions(left, right) {
  const a = versionParts(left, "version");
  const b = versionParts(right, "previous version");
  for (let index = 0; index < 3; index += 1) if (a[index] !== b[index]) return a[index] - b[index];
  return 0;
}

function normalizeReleaseManifest(value, policy) {
  exactKeys(value, ["approval", "artifacts", "evidence", "schema", "schemaVersion", "source", "version"], "release manifest");
  requireString(value.schema, "netlist-studio.release-manifest", "release manifest schema");
  if (value.schemaVersion !== 2) throw new PolicyViolation("release manifest schemaVersion must be 2");
  versionParts(value.version, "release manifest version");
  exactKeys(value.source, ["commit", "repository", "tag", "tagObject"], "release manifest source");
  requireString(value.source.repository, policy.repositories.source.fullName, "release manifest source repository");
  requirePattern(value.source.commit, OBJECT_ID, "release manifest source commit");
  requireString(value.source.tag, `v${value.version}`, "release manifest source tag");
  requirePattern(value.source.tagObject, OBJECT_ID, "release manifest source tag object");
  if (!Array.isArray(value.artifacts) || value.artifacts.length !== 2) throw new PolicyViolation("release manifest must contain ZIP and DMG");
  const expectedNames = [`Netlist-Studio-${value.version}-arm64.dmg`, `Netlist-Studio-${value.version}-arm64.zip`];
  for (const [index, artifact] of value.artifacts.entries()) {
    exactKeys(artifact, ["name", "sha256", "size"], `release artifact ${index}`);
    requireString(artifact.name, expectedNames[index], `release artifact ${index} name`);
    requirePattern(artifact.sha256, SHA256, `release artifact ${index} sha256`);
    positiveInteger(artifact.size, `release artifact ${index} size`);
  }
  exactKeys(value.evidence, ["name", "sha256", "size"], "release manifest evidence");
  requireString(value.evidence.name, "release-evidence.json", "release evidence name");
  requirePattern(value.evidence.sha256, SHA256, "release evidence sha256");
  positiveInteger(value.evidence.size, "release evidence size");
  exactKeys(value.approval, ["approved", "confirmation", "evidence", "githubId", "releaseOwner", "signingKeyFingerprint"], "release approval");
  if (value.approval.approved !== true || value.approval.githubId !== policy.releaseTag.ownerGithubId || value.approval.signingKeyFingerprint !== policy.releaseTag.signingKeyFingerprint) throw new PolicyViolation("release approval is not canonical");
  requireString(value.approval.confirmation, `RELEASE OWNER APPROVE v${value.version}`, "release approval confirmation");
  if (typeof value.approval.releaseOwner !== "string" || value.approval.releaseOwner.length === 0) throw new PolicyViolation("release owner is required");
  exactKeys(value.approval.evidence, ["commit", "path", "repository", "sha256"], "release approval evidence");
  requireString(value.approval.evidence.repository, policy.repositories.source.fullName, "release approval evidence repository");
  requirePattern(value.approval.evidence.commit, OBJECT_ID, "release approval evidence commit");
  requirePattern(value.approval.evidence.sha256, SHA256, "release approval evidence sha256");
  if (typeof value.approval.evidence.path !== "string" || value.approval.evidence.path.length === 0 || value.approval.evidence.path.startsWith("/") || value.approval.evidence.path.split("/").includes("..")) throw new PolicyViolation("release approval evidence path is invalid");
  return value;
}

export function parseReleaseManifest(text, policy) {
  return normalizeReleaseManifest(parseJsonStrict(text), policy);
}

export function validateReleaseManifestUpdate({ base, candidate, policy }) {
  const baseBytes = base.files.get("release-manifest.json");
  const candidateBytes = candidate.files.get("release-manifest.json");
  if (!baseBytes || !candidateBytes) throw new PolicyViolation("release manifest must exist on both base and candidate");
  const previous = parseReleaseManifest(baseBytes.toString("utf8"), policy);
  const next = parseReleaseManifest(candidateBytes.toString("utf8"), policy);
  if (compareVersions(next.version, previous.version) <= 0) throw new PolicyViolation("release manifest version must strictly increase");
  return Object.freeze({ next, previous });
}

function normalizeAsset(asset, expectedName, expectedUrl, label) {
  exactKeys(asset, ["id", "name", "sha256", "sha512", "size", "url"], label);
  requireString(asset.name, expectedName, `${label} name`);
  positiveInteger(asset.id, `${label} id`);
  requirePattern(asset.sha256, SHA256, `${label} sha256`);
  requirePattern(asset.sha512, SHA512, `${label} sha512`);
  positiveInteger(asset.size, `${label} size`);
  requireString(asset.url, expectedUrl, `${label} URL`);
  return { name: asset.name, id: asset.id, sha256: asset.sha256, sha512: asset.sha512, size: asset.size, url: asset.url };
}

export function parseChannelBinding(text, policy) {
  if (Buffer.byteLength(text, "utf8") > policy.limits.channelBindingBytes) throw new PolicyViolation("channel binding is oversized");
  const value = parseJsonStrict(text, policy.limits.channelBindingBytes);
  exactKeys(value, ["arch", "assets", "channel", "manifest", "platform", "previousVersion", "release", "schema", "schemaVersion", "source", "version"], "channel binding");
  requireString(value.schema, "netlist-studio.update-channel-binding", "channel binding schema");
  if (value.schemaVersion !== 1) throw new PolicyViolation("channel binding schemaVersion must be 1");
  requireString(value.channel, policy.channel.name, "channel");
  requireString(value.platform, policy.channel.platform, "platform");
  requireString(value.arch, policy.channel.arch, "arch");
  versionParts(value.version, "channel version");
  versionParts(value.previousVersion, "channel previousVersion");
  if (compareVersions(value.version, value.previousVersion) <= 0) throw new PolicyViolation("channel version must increase");
  exactKeys(value.source, ["commit", "repository", "tag", "tagObject"], "channel source");
  requireString(value.source.repository, policy.repositories.source.fullName, "channel source repository");
  requirePattern(value.source.commit, OBJECT_ID, "channel source commit");
  requireString(value.source.tag, `v${value.version}`, "channel source tag");
  requirePattern(value.source.tagObject, OBJECT_ID, "channel source tag object");
  exactKeys(value.release, ["id", "immutable", "makeLatest", "prerelease", "publishedAt", "repository", "tag", "tagObject", "tagTarget"], "channel release");
  requireString(value.release.repository, policy.repositories.release.fullName, "channel release repository");
  positiveInteger(value.release.id, "channel release id");
  requireString(value.release.tag, `v${value.version}`, "channel release tag");
  requirePattern(value.release.tagObject, OBJECT_ID, "channel release tag object");
  requirePattern(value.release.tagTarget, OBJECT_ID, "channel release tag target");
  if (value.release.immutable !== true || value.release.prerelease !== false || value.release.makeLatest !== false) throw new PolicyViolation("channel release flags are invalid");
  requirePattern(value.release.publishedAt, UTC_SECONDS, "channel release publishedAt");
  if (Number.isNaN(Date.parse(value.release.publishedAt))) throw new PolicyViolation("channel release publishedAt is invalid");
  exactKeys(value.manifest, ["id", "name", "sha256", "size"], "channel manifest");
  requireString(value.manifest.name, "release-manifest.json", "channel manifest name");
  positiveInteger(value.manifest.id, "channel manifest id");
  requirePattern(value.manifest.sha256, SHA256, "channel manifest sha256");
  positiveInteger(value.manifest.size, "channel manifest size");
  if (!Array.isArray(value.assets) || value.assets.length !== 2) throw new PolicyViolation("channel assets must contain ZIP and DMG");
  const tag = `v${value.version}`;
  const zipName = `Netlist-Studio-${value.version}-arm64.zip`;
  const dmgName = `Netlist-Studio-${value.version}-arm64.dmg`;
  const prefix = `https://github.com/${policy.repositories.release.fullName}/releases/download/${tag}/`;
  const zip = normalizeAsset(value.assets[0], zipName, `${prefix}${zipName}`, "channel ZIP");
  const dmg = normalizeAsset(value.assets[1], dmgName, `${prefix}${dmgName}`, "channel DMG");
  const normalized = {
    schema: value.schema,
    schemaVersion: 1,
    channel: value.channel,
    platform: value.platform,
    arch: value.arch,
    version: value.version,
    previousVersion: value.previousVersion,
    source: { repository: value.source.repository, commit: value.source.commit, tag: value.source.tag, tagObject: value.source.tagObject },
    release: { repository: value.release.repository, id: value.release.id, tag: value.release.tag, tagObject: value.release.tagObject, tagTarget: value.release.tagTarget, immutable: true, prerelease: false, makeLatest: false, publishedAt: value.release.publishedAt },
    manifest: { name: value.manifest.name, id: value.manifest.id, sha256: value.manifest.sha256, size: value.manifest.size },
    assets: [zip, dmg],
  };
  if (text !== `${JSON.stringify(normalized, null, 2)}\n`) throw new PolicyViolation("channel binding JSON bytes are not canonical");
  return normalized;
}

export function expectedLatestMac(binding) {
  const [zip, dmg] = binding.assets;
  return [
    `version: ${binding.version}`,
    "files:",
    `  - url: ${zip.url}`,
    `    sha512: ${zip.sha512}`,
    `    size: ${zip.size}`,
    `  - url: ${dmg.url}`,
    `    sha512: ${dmg.sha512}`,
    `    size: ${dmg.size}`,
    `path: ${zip.url}`,
    `sha512: ${zip.sha512}`,
    `releaseDate: '${new Date(binding.release.publishedAt).toISOString()}'`,
    "",
  ].join("\n");
}

export function validateStableChannelSnapshot({ base, candidate, policy }) {
  const directory = policy.channel.directory;
  const bindingPath = `${directory}/channel-binding.json`;
  const metadataPath = `${directory}/latest-mac.yml`;
  const bindingBytes = candidate.files.get(bindingPath);
  const metadataBytes = candidate.files.get(metadataPath);
  if (!bindingBytes || !metadataBytes) throw new PolicyViolation("stable channel requires exact binding and metadata files");
  if (metadataBytes.length > policy.limits.latestMacBytes) throw new PolicyViolation("latest-mac.yml is oversized");
  const binding = parseChannelBinding(bindingBytes.toString("utf8"), policy);
  if (metadataBytes.toString("utf8") !== expectedLatestMac(binding)) throw new PolicyViolation("latest-mac.yml does not exactly match channel binding");
  const manifestBytes = candidate.files.get("release-manifest.json");
  if (!manifestBytes) throw new PolicyViolation("release manifest is missing");
  const manifest = parseReleaseManifest(manifestBytes.toString("utf8"), policy);
  if (manifest.version !== binding.version || manifest.source.repository !== binding.source.repository || manifest.source.commit !== binding.source.commit || manifest.source.tag !== binding.source.tag || manifest.source.tagObject !== binding.source.tagObject) {
    throw new PolicyViolation("channel source does not match release manifest");
  }
  const artifacts = new Map(manifest.artifacts.map((artifact) => [artifact.name, artifact]));
  for (const asset of binding.assets) {
    const manifestArtifact = artifacts.get(asset.name);
    if (!manifestArtifact || manifestArtifact.sha256 !== asset.sha256 || manifestArtifact.size !== asset.size) throw new PolicyViolation(`channel asset does not match release manifest: ${asset.name}`);
  }
  const baseBinding = base.files.get(bindingPath);
  const baseMetadata = base.files.get(metadataPath);
  if (Boolean(baseBinding) !== Boolean(baseMetadata)) throw new PolicyViolation("base stable channel is incomplete");
  if (!baseBinding) {
    if (binding.version !== policy.channel.initialVersion || binding.previousVersion !== policy.channel.initialPreviousVersion) throw new PolicyViolation("initial stable channel version pair is invalid");
  } else {
    const previous = parseChannelBinding(baseBinding.toString("utf8"), policy);
    if (baseMetadata.toString("utf8") !== expectedLatestMac(previous)) throw new PolicyViolation("base stable channel metadata is corrupt");
    if (binding.previousVersion !== previous.version || compareVersions(binding.version, previous.version) <= 0) throw new PolicyViolation("stable channel update is not a strict continuation");
  }
  return Object.freeze({ binding, classification: "stable-channel" });
}

function validateProviderTarget(target) {
  exactKeys(target, ["actions", "branch", "merge", "ruleset", "workflow"], "provider target");
  requireString(target.branch, "main", "provider target branch");
  exactKeys(target.actions, ["allowedActions", "enabled", "shaPinningRequired"], "provider Actions target");
  if (target.actions.enabled !== true || target.actions.allowedActions !== "all" || target.actions.shaPinningRequired !== true) throw new PolicyViolation("provider Actions target is invalid");
  exactKeys(target.workflow, ["canApprovePullRequestReviews", "defaultWorkflowPermissions"], "provider workflow target");
  if (target.workflow.defaultWorkflowPermissions !== "read" || target.workflow.canApprovePullRequestReviews !== false) throw new PolicyViolation("provider workflow permission target is invalid");
  exactKeys(target.merge, ["allowAutoMerge", "allowMergeCommit", "allowRebaseMerge", "allowSquashMerge", "deleteBranchOnMerge"], "provider merge target");
  if (target.merge.allowMergeCommit !== true || target.merge.allowSquashMerge !== false || target.merge.allowRebaseMerge !== false || target.merge.allowAutoMerge !== false || target.merge.deleteBranchOnMerge !== true) throw new PolicyViolation("provider merge target is invalid");
  exactKeys(target.ruleset, ["allowBypass", "allowDeletion", "allowForcePush", "conversationResolutionRequired", "enforcement", "mergeMethods", "name", "requiredApprovals", "requiredChecks", "requiredSignatures", "strictRequiredChecks"], "provider ruleset target");
  if (target.ruleset.name !== "protect-main" || target.ruleset.enforcement !== "active" || target.ruleset.allowBypass !== false || target.ruleset.allowDeletion !== false || target.ruleset.allowForcePush !== false || target.ruleset.conversationResolutionRequired !== true || target.ruleset.requiredApprovals !== 0 || target.ruleset.requiredSignatures !== true || target.ruleset.strictRequiredChecks !== true || canonicalJson(target.ruleset.mergeMethods) !== canonicalJson(["merge"])) throw new PolicyViolation("provider ruleset target is invalid");
  if (!Array.isArray(target.ruleset.requiredChecks) || target.ruleset.requiredChecks.length !== 2) throw new PolicyViolation("provider required checks must contain two source-bound contexts");
  const expectedContexts = ["channel-data", "trusted-policy"];
  const integrationIds = [];
  for (const [index, check] of target.ruleset.requiredChecks.entries()) {
    exactKeys(check, ["context", "integrationId"], `provider required check ${index}`);
    requireString(check.context, expectedContexts[index], `provider required check ${index} context`);
    integrationIds.push(positiveInteger(check.integrationId, `provider required check ${index} integrationId`));
  }
  if (new Set(integrationIds).size !== 1) throw new PolicyViolation("required contexts must be bound to one GitHub Actions integration");
  return target;
}

export function validateProviderFiles(candidate, policy) {
  const requestBytes = candidate.files.get("provider-policy.request.json");
  const readbackBytes = candidate.files.get("provider-policy.readback.json");
  if (!requestBytes || !readbackBytes) throw new PolicyViolation("provider policy request and read-back are both required");
  const requestText = requestBytes.toString("utf8");
  const readbackText = readbackBytes.toString("utf8");
  const request = parseJsonStrict(requestText);
  const readback = parseJsonStrict(readbackText);
  if (requestText !== canonicalJson(request) || readbackText !== canonicalJson(readback)) throw new PolicyViolation("provider policy evidence must be canonical JSON");
  exactKeys(request, ["exceptionId", "repository", "rollbackSnapshot", "schema", "schemaVersion", "target"], "provider policy request");
  if (request.schema !== "netlist-studio.provider-policy-request" || request.schemaVersion !== 1 || request.exceptionId !== policy.providerException.exceptionId) throw new PolicyViolation("provider policy request schema is invalid");
  exactKeys(request.repository, ["branch", "fullName", "id"], "provider policy repository");
  if (request.repository.branch !== "main" || request.repository.fullName !== policy.repositories.release.fullName || request.repository.id !== policy.repositories.release.id) throw new PolicyViolation("provider policy repository identity drifted");
  exactKeys(request.rollbackSnapshot, ["sha256", "storage"], "provider rollback snapshot");
  requirePattern(request.rollbackSnapshot.sha256, SHA256, "provider rollback snapshot sha256");
  requireString(request.rollbackSnapshot.storage, "external-ephemeral", "provider rollback snapshot storage");
  validateProviderTarget(request.target);

  exactKeys(readback, ["checkSources", "exceptionId", "observedAt", "repositoryId", "requestSha256", "rulesetId", "schema", "schemaVersion", "target"], "provider policy read-back");
  if (readback.schema !== "netlist-studio.provider-policy-readback" || readback.schemaVersion !== 1 || readback.exceptionId !== policy.providerException.exceptionId || readback.repositoryId !== policy.repositories.release.id) throw new PolicyViolation("provider policy read-back schema is invalid");
  requirePattern(readback.observedAt, UTC_SECONDS, "provider policy observedAt");
  if (Number.isNaN(Date.parse(readback.observedAt))) throw new PolicyViolation("provider policy observedAt is invalid");
  positiveInteger(readback.rulesetId, "provider ruleset id");
  requireString(readback.requestSha256, sha256Text(requestText), "provider request sha256");
  validateProviderTarget(readback.target);
  if (canonicalJson(readback.target) !== canonicalJson(request.target)) throw new PolicyViolation("provider read-back does not match the requested target");
  if (!Array.isArray(readback.checkSources) || readback.checkSources.length !== 2) throw new PolicyViolation("provider check source evidence is incomplete");
  for (const [index, source] of readback.checkSources.entries()) {
    exactKeys(source, ["attempt", "context", "headSha", "integrationId", "runId", "slug"], `provider check source ${index}`);
    requireString(source.context, request.target.ruleset.requiredChecks[index].context, `provider check source ${index} context`);
    requireString(source.slug, "github-actions", `provider check source ${index} slug`);
    if (source.integrationId !== request.target.ruleset.requiredChecks[index].integrationId) throw new PolicyViolation(`provider check source ${index} integration drifted`);
    requirePattern(source.headSha, FULL_SHA, `provider check source ${index} headSha`);
    positiveInteger(source.runId, `provider check source ${index} runId`);
    positiveInteger(source.attempt, `provider check source ${index} attempt`);
  }
  return Object.freeze({ classification: "provider-policy", readback, request });
}

function canonicalSnapshotJson(candidate, relativePath) {
  const bytes = candidate.files.get(relativePath);
  if (!bytes) throw new PolicyViolation(`policy maintenance candidate is missing ${relativePath}`);
  const text = bytes.toString("utf8");
  const value = parseJsonStrict(text);
  if (text !== canonicalJson(value)) throw new PolicyViolation(`policy maintenance candidate is not canonical: ${relativePath}`);
  return { text, value };
}

export function validatePolicyMaintenance({ candidate, contract, policy }) {
  for (const relativePath of policy.bootstrap.requiredPaths) {
    if (!candidate.files.has(relativePath)) throw new PolicyViolation(`policy maintenance candidate is missing protected path: ${relativePath}`);
  }
  const candidateContract = canonicalSnapshotJson(candidate, "pipeline.contract.json").value;
  const candidatePolicy = canonicalSnapshotJson(candidate, "channel-policy.json").value;
  validateConfiguration(candidateContract, candidatePolicy);
  if (canonicalJson(candidateContract) !== canonicalJson(contract) || canonicalJson(candidatePolicy) !== canonicalJson(policy)) throw new PolicyViolation("policy maintenance candidate may not redefine authority-bearing configuration");
  const workflows = {
    "manual-promotion": candidateContract.trustZones["manual-promotion"].workflowPath,
    "source-ci": candidateContract.trustZones["source-ci"].workflowPath,
    "trusted-policy": candidateContract.trustZones["trusted-policy"].workflowPath,
  };
  for (const [role, relativePath] of Object.entries(workflows)) {
    const bytes = candidate.files.get(relativePath);
    if (!bytes) throw new PolicyViolation(`policy maintenance candidate is missing workflow: ${relativePath}`);
    validateWorkflowText(bytes.toString("utf8"), role, contract);
  }
  return Object.freeze({
    classification: "policy-maintenance",
    contractSha256: sha256Text(canonicalJson(candidateContract)),
    policySha256: sha256Text(canonicalJson(candidatePolicy)),
  });
}

export async function validateChange({ base, candidate, baseSha, contract, policy }) {
  validateConfiguration(contract, policy);
  const paths = changedPaths(base, candidate);
  const classification = classifyChangedPaths(paths, { baseHasPolicy: base.files.has("pipeline.contract.json"), baseSha, policy });
  let details = null;
  if (classification === "stable-channel") details = validateStableChannelSnapshot({ base, candidate, policy });
  else if (classification === "release-manifest") details = validateReleaseManifestUpdate({ base, candidate, policy });
  else if (classification === "provider-policy") details = validateProviderFiles(candidate, policy);
  else if (classification === "policy-maintenance") details = validatePolicyMaintenance({ candidate, contract, policy });
  return Object.freeze({ classification, changedPaths: paths, details });
}

export async function githubRequest(endpoint, { token = process.env.GITHUB_TOKEN, method = "GET", body, accept = "application/vnd.github+json" } = {}) {
  if (!token) throw new EvidenceUnavailable("GITHUB_TOKEN is required");
  let response;
  try {
    response = await fetch(`https://api.github.com${endpoint}`, {
      method,
      headers: { Accept: accept, Authorization: `Bearer ${token}`, "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "netlist-studio-channel-policy/1" },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "error",
      signal: AbortSignal.timeout(15000),
    });
  } catch {
    throw new EvidenceUnavailable("GitHub API request failed");
  }
  if (!response.ok) throw new EvidenceUnavailable(`GitHub API returned HTTP ${response.status}`);
  if (response.status === 204) return null;
  try {
    return await response.json();
  } catch {
    throw new EvidenceUnavailable("GitHub API returned invalid JSON");
  }
}

async function fetchPublicAsset(url, maximumBytes) {
  if (typeof url !== "string" || !url.startsWith("https://github.com/y-asami3534/netlist-studio-releases/releases/download/")) throw new PolicyViolation("public release asset URL is not canonical");
  let response;
  try {
    response = await fetch(url, {
      headers: { Accept: "application/octet-stream", "User-Agent": "netlist-studio-channel-policy/1" },
      redirect: "follow",
      signal: AbortSignal.timeout(15000),
    });
  } catch {
    throw new EvidenceUnavailable("public release asset request failed");
  }
  const declared = Number(response.headers.get("content-length"));
  if (!response.ok || (Number.isFinite(declared) && declared > maximumBytes)) throw new EvidenceUnavailable("public release asset is unavailable or oversized");
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > maximumBytes) throw new EvidenceUnavailable("public release asset exceeds its size limit");
  return bytes;
}

function decodeContentsFile(payload, expectedPath, maximumBytes) {
  if (payload?.type !== "file" || payload?.path !== expectedPath || payload?.encoding !== "base64" || typeof payload?.content !== "string" || !Number.isSafeInteger(payload?.size) || payload.size > maximumBytes) throw new EvidenceUnavailable(`tagged repository file is unavailable: ${expectedPath}`);
  const bytes = Buffer.from(payload.content.replace(/\n/gu, ""), "base64");
  if (bytes.length !== payload.size) throw new EvidenceUnavailable(`tagged repository file size drifted: ${expectedPath}`);
  return bytes;
}

function normalizeReleaseAsset(asset, expected) {
  if (asset?.id !== expected.id || asset?.name !== expected.name || asset?.size !== expected.size || asset?.browser_download_url !== expected.url || asset?.digest !== `sha256:${expected.sha256}` || asset?.state !== "uploaded") throw new PolicyViolation(`GitHub Release asset drifted: ${expected.name}`);
  return Object.freeze({ id: asset.id, name: asset.name, sha256: asset.digest.slice(7), size: asset.size, url: asset.browser_download_url });
}

function sshSignatureFingerprint(signature) {
  if (typeof signature !== "string") throw new PolicyViolation("release tag SSH signature is unavailable");
  const match = signature.match(/^-----BEGIN SSH SIGNATURE-----\n([A-Za-z0-9+/=\n]+)\n-----END SSH SIGNATURE-----\n?$/u);
  if (!match) throw new PolicyViolation("release tag SSH signature armor is invalid");
  const bytes = Buffer.from(match[1].replace(/\n/gu, ""), "base64");
  if (bytes.length < 14 || bytes.subarray(0, 6).toString("ascii") !== "SSHSIG" || bytes.readUInt32BE(6) !== 1) throw new PolicyViolation("release tag SSH signature envelope is invalid");
  const publicKeyLength = bytes.readUInt32BE(10);
  if (publicKeyLength <= 0 || 14 + publicKeyLength > bytes.length) throw new PolicyViolation("release tag SSH public key is invalid");
  return `SHA256:${createHash("sha256").update(bytes.subarray(14, 14 + publicKeyLength)).digest("base64").replace(/=+$/u, "")}`;
}

function validateVerifiedReleaseTag(tag, binding, manifest, policy) {
  const signature = tag?.verification?.signature;
  if (sshSignatureFingerprint(signature) !== policy.releaseTag.signingKeyFingerprint) throw new PolicyViolation("release tag signing key fingerprint drifted");
  if (tag?.tagger?.email !== policy.releaseTag.signingPrincipal || tag?.tagger?.name !== manifest.approval.releaseOwner) throw new PolicyViolation("release tag signer identity drifted");
  const artifactByName = new Map(manifest.artifacts.map((artifact) => [artifact.name, artifact]));
  const dmg = artifactByName.get(`Netlist-Studio-${binding.version}-arm64.dmg`);
  const zip = artifactByName.get(`Netlist-Studio-${binding.version}-arm64.zip`);
  const signedMessage = [
    `Netlist Studio v${binding.version}`,
    "",
    `Release-Schema: ${policy.releaseTag.messageSchema}`,
    `Version: ${binding.version}`,
    `Repository: ${policy.repositories.release.fullName}`,
    `Source-Repository: ${binding.source.repository}`,
    `Source-Commit: ${binding.source.commit}`,
    `DMG-SHA256: ${dmg?.sha256 ?? ""}`,
    `ZIP-SHA256: ${zip?.sha256 ?? ""}`,
    `Evidence-SHA256: ${manifest.evidence.sha256}`,
    `Release-Owner: ${manifest.approval.releaseOwner}`,
    "Approval: approved",
    `Signing-Key-Fingerprint: ${policy.releaseTag.signingKeyFingerprint}`,
    "",
  ].join("\n");
  if (typeof tag.message !== "string" || !tag.message.startsWith(signedMessage) || tag.message.slice(signedMessage.length).trimEnd() !== signature.trimEnd()) throw new PolicyViolation("release tag signed message drifted");
}

export function validateRemoteReleaseSnapshot({ binding, candidateManifestBytes, policy, snapshot }) {
  if (!Buffer.isBuffer(candidateManifestBytes)) throw new EvidenceUnavailable("candidate release manifest bytes are unavailable");
  const release = snapshot?.release;
  if (release?.id !== binding.release.id || release?.tag_name !== binding.release.tag || release?.draft !== false || release?.prerelease !== false || release?.immutable !== true || release?.published_at !== binding.release.publishedAt) throw new PolicyViolation("GitHub Release identity or immutable flags drifted");
  if (snapshot?.latestReleaseId === binding.release.id) throw new PolicyViolation("stable channel release must not become GitHub Latest");
  if (snapshot?.tagRef?.ref !== `refs/tags/${binding.release.tag}` || snapshot?.tagRef?.object?.type !== "tag" || snapshot?.tagRef?.object?.sha !== binding.release.tagObject) throw new PolicyViolation("release tag ref drifted");
  const tag = snapshot?.tagObject;
  if (tag?.sha !== binding.release.tagObject || tag?.tag !== binding.release.tag || tag?.object?.type !== "commit" || tag?.object?.sha !== binding.release.tagTarget || tag?.verification?.verified !== true || tag?.verification?.reason !== "valid") throw new PolicyViolation("release tag object is not the exact verified annotated tag");

  const manifest = parseReleaseManifest(candidateManifestBytes.toString("utf8"), policy);
  validateVerifiedReleaseTag(tag, binding, manifest, policy);
  const prefix = `https://github.com/${policy.repositories.release.fullName}/releases/download/${binding.release.tag}/`;
  const expected = [
    ...binding.assets,
    { id: binding.manifest.id, name: binding.manifest.name, sha256: binding.manifest.sha256, size: binding.manifest.size, url: `${prefix}${binding.manifest.name}` },
  ];
  if (!Array.isArray(release.assets) || release.assets.length !== expected.length) throw new PolicyViolation("GitHub Release must contain the exact ZIP, DMG, and manifest assets");
  const byName = new Map(release.assets.map((asset) => [asset.name, asset]));
  if (byName.size !== expected.length) throw new PolicyViolation("GitHub Release asset names must be unique");
  for (const asset of expected) {
    const actual = byName.get(asset.name);
    normalizeReleaseAsset(actual, asset);
  }
  if (!Buffer.isBuffer(snapshot.taggedManifestBytes) || !Buffer.isBuffer(snapshot.releaseManifestAssetBytes)) throw new EvidenceUnavailable("release manifest byte evidence is unavailable");
  if (!candidateManifestBytes.equals(snapshot.taggedManifestBytes) || !candidateManifestBytes.equals(snapshot.releaseManifestAssetBytes)) throw new PolicyViolation("release manifest bytes differ across candidate, signed tag, and Release asset");
  if (candidateManifestBytes.length !== binding.manifest.size || createHash("sha256").update(candidateManifestBytes).digest("hex") !== binding.manifest.sha256) throw new PolicyViolation("release manifest digest or size drifted");
  return Object.freeze({ releaseId: release.id, tagObject: tag.sha, tagTarget: tag.object.sha });
}

export async function collectRemoteReleaseEvidence({ binding, candidateManifestBytes, policy }) {
  const repository = policy.repositories.release.fullName.split("/").map(encodeURIComponent).join("/");
  const tagName = encodeURIComponent(binding.release.tag);
  const [release, latest, tagRef, tagObject, taggedManifest] = await Promise.all([
    githubRequest(`/repos/${repository}/releases/tags/${tagName}`),
    githubRequest(`/repos/${repository}/releases/latest`),
    githubRequest(`/repos/${repository}/git/ref/tags/${tagName}`),
    githubRequest(`/repos/${repository}/git/tags/${binding.release.tagObject}`),
    githubRequest(`/repos/${repository}/contents/release-manifest.json?ref=${encodeURIComponent(binding.release.tagTarget)}`),
  ]);
  const manifestAsset = Array.isArray(release?.assets) ? release.assets.find((asset) => asset.name === binding.manifest.name && asset.id === binding.manifest.id) : null;
  if (!manifestAsset) throw new PolicyViolation("release manifest asset identity drifted");
  const releaseManifestAssetBytes = await fetchPublicAsset(manifestAsset.browser_download_url, policy.limits.maximumFileBytes);
  return validateRemoteReleaseSnapshot({
    binding,
    candidateManifestBytes,
    policy,
    snapshot: {
      latestReleaseId: latest?.id,
      release,
      releaseManifestAssetBytes,
      taggedManifestBytes: decodeContentsFile(taggedManifest, "release-manifest.json", policy.limits.maximumFileBytes),
      tagObject,
      tagRef,
    },
  });
}

export async function fetchGithubSnapshot(repository, sha, policy) {
  requirePattern(sha, FULL_SHA, "snapshot SHA");
  const encoded = repository.split("/").map(encodeURIComponent).join("/");
  const tree = await githubRequest(`/repos/${encoded}/git/trees/${sha}?recursive=1`);
  if (tree?.truncated || !Array.isArray(tree?.tree)) throw new EvidenceUnavailable("GitHub tree inventory is unavailable or truncated");
  const files = new Map();
  let totalBytes = 0;
  for (const entry of tree.tree) {
    if (entry.type === "tree") continue;
    if (entry.type !== "blob" || entry.mode !== "100644") throw new PolicyViolation(`non-regular Git entry is forbidden: ${entry.path}`);
    if (!Number.isSafeInteger(entry.size) || entry.size > policy.limits.maximumFileBytes) throw new PolicyViolation(`Git blob is oversized: ${entry.path}`);
    totalBytes += entry.size;
    if (totalBytes > policy.limits.maximumRepositoryBytes || files.size + 1 > policy.limits.maximumTreeEntries) throw new PolicyViolation("Git tree exceeds policy limits");
    const blob = await githubRequest(`/repos/${encoded}/git/blobs/${entry.sha}`);
    if (blob?.encoding !== "base64" || typeof blob.content !== "string") throw new EvidenceUnavailable(`Git blob is unavailable: ${entry.path}`);
    const bytes = Buffer.from(blob.content.replace(/\n/gu, ""), "base64");
    if (bytes.length !== entry.size) throw new EvidenceUnavailable(`Git blob size changed: ${entry.path}`);
    files.set(entry.path, bytes);
  }
  const allowed = allowedRepositoryPaths(policy);
  for (const relativePath of files.keys()) if (!allowed.has(relativePath)) throw new PolicyViolation(`unexpected repository path: ${relativePath}`);
  return Object.freeze({ root: null, files });
}

export async function collectGithubChange({ repository, prNumber, baseSha, headSha, contract, policy }) {
  if (repository !== contract.canonical.repository.fullName) throw new PolicyViolation("repository is not canonical");
  const encoded = repository.split("/").map(encodeURIComponent).join("/");
  const pr = await githubRequest(`/repos/${encoded}/pulls/${encodeURIComponent(prNumber)}`);
  if (pr?.state !== "open" || pr?.base?.ref !== contract.canonical.repository.branch || pr?.base?.sha !== baseSha || pr?.head?.sha !== headSha || pr?.head?.repo?.full_name !== repository) throw new PolicyViolation("current pull request base/head/repository binding changed");
  const [base, candidate] = await Promise.all([
    fetchGithubSnapshot(repository, baseSha, policy),
    fetchGithubSnapshot(repository, headSha, policy),
  ]);
  const result = await validateChange({ base, candidate, baseSha, contract, policy });
  if (result.classification === "stable-channel") {
    await collectRemoteReleaseEvidence({ binding: result.details.binding, candidateManifestBytes: candidate.files.get("release-manifest.json"), policy });
  }
  return result;
}

export async function atomicWriteJson(outputPath, value) {
  if (!path.isAbsolute(outputPath)) throw new UsageError("output path must be absolute");
  const directory = path.dirname(outputPath);
  const metadata = await lstat(directory).catch(() => null);
  if (!metadata?.isDirectory() || metadata.isSymbolicLink()) throw new UsageError("output directory must be real");
  const handle = await open(outputPath, "wx", 0o600);
  try {
    await handle.writeFile(canonicalJson(value), "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
}

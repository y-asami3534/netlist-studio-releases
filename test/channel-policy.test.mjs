import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  PolicyViolation,
  UsageError,
  canonicalJson,
  classifyChangedPaths,
  expectedLatestMac,
  parseChannelBinding,
  parseJsonStrict,
  readRepositorySnapshot,
  validateConfiguration,
  validateChange,
  validateProviderFiles,
  validatePolicyMaintenance,
  validateReleaseManifestUpdate,
  validateRemoteReleaseSnapshot,
  validateStableChannelSnapshot,
  validateWorkflowText,
} from "../.secure-ci-cd/policy-lib.mjs";
import {
  publishTrustedStatus,
  validatePublicationSnapshot,
  validateStatusResponse,
} from "../.secure-ci-cd/verify-trusted-publication.mjs";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const contract = parseJsonStrict(await (await import("node:fs/promises")).readFile(path.join(repositoryRoot, "pipeline.contract.json"), "utf8"));
const policy = parseJsonStrict(await (await import("node:fs/promises")).readFile(path.join(repositoryRoot, "channel-policy.json"), "utf8"));
const roots = [];
const releaseTagSignature = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgtxWhK/EDM87ikYMsPLnKe4Olqf
k08Ww8WMccU3IGrKgAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQCJ8HWaUEUPIAmXGyFrzfMYecPQBOKzlaZ6Hf59/XYaC+PBpqZ/aKWS9KX+roBePqN
RV5+grJ4ca3eQ+Ft704wc=
-----END SSH SIGNATURE-----
`;

test.after(async () => {
  await Promise.all(roots.map((root) => rm(root, { recursive: true, force: true })));
});

function releaseManifest(version = "0.40.0") {
  return {
    schema: "netlist-studio.release-manifest",
    schemaVersion: 2,
    version,
    source: {
      repository: "y-asami3534/netlist-studio",
      commit: "1".repeat(40),
      tag: `v${version}`,
      tagObject: "2".repeat(40),
    },
    artifacts: [
      { name: `Netlist-Studio-${version}-arm64.dmg`, sha256: "b".repeat(64), size: 456 },
      { name: `Netlist-Studio-${version}-arm64.zip`, sha256: "a".repeat(64), size: 123 },
    ],
    evidence: { name: "release-evidence.json", sha256: "c".repeat(64), size: 789 },
    approval: {
      releaseOwner: "浅見悠介",
      githubId: 50958596,
      approved: true,
      confirmation: `RELEASE OWNER APPROVE v${version}`,
      signingKeyFingerprint: "SHA256:byJQrGJp2En8bA2tWQcD73wnEnJRGjSz7tpRwoJWA4w",
      evidence: { repository: "y-asami3534/netlist-studio", commit: "3".repeat(40), path: "reports/release.md", sha256: "d".repeat(64) },
    },
  };
}

function binding({ version = "0.40.0", previousVersion = "0.39.23" } = {}) {
  const tag = `v${version}`;
  const prefix = `https://github.com/y-asami3534/netlist-studio-releases/releases/download/${tag}/`;
  return {
    schema: "netlist-studio.update-channel-binding",
    schemaVersion: 1,
    channel: "stable",
    platform: "macos",
    arch: "arm64",
    version,
    previousVersion,
    source: { repository: "y-asami3534/netlist-studio", commit: "1".repeat(40), tag, tagObject: "2".repeat(40) },
    release: { repository: "y-asami3534/netlist-studio-releases", id: 42, tag, tagObject: "4".repeat(40), tagTarget: "5".repeat(40), immutable: true, prerelease: false, makeLatest: false, publishedAt: "2026-08-01T01:02:03Z" },
    manifest: { name: "release-manifest.json", id: 103, sha256: "e".repeat(64), size: 1400 },
    assets: [
      { name: `Netlist-Studio-${version}-arm64.zip`, id: 101, sha256: "a".repeat(64), sha512: `${"A".repeat(86)}==`, size: 123, url: `${prefix}Netlist-Studio-${version}-arm64.zip` },
      { name: `Netlist-Studio-${version}-arm64.dmg`, id: 102, sha256: "b".repeat(64), sha512: `${"B".repeat(86)}==`, size: 456, url: `${prefix}Netlist-Studio-${version}-arm64.dmg` },
    ],
  };
}

function snapshot(entries) {
  return { files: new Map(Object.entries(entries).map(([name, value]) => [name, Buffer.from(value)])) };
}

function cloneSnapshot(value) {
  return { files: new Map([...value.files].map(([name, bytes]) => [name, Buffer.from(bytes)])) };
}

function publicationFixture() {
  const args = {
    attempt: "1",
    baseSha: "1".repeat(40),
    context: "trusted-policy",
    description: "default branch policy validation passed",
    headSha: "2".repeat(40),
    prNumber: "7",
    repository: "y-asami3534/netlist-studio-releases",
    runId: "10",
    state: "success",
    targetUrl: "https://github.com/y-asami3534/netlist-studio-releases/actions/runs/10/attempts/1",
    workflowPath: ".github/workflows/channel-trusted-policy.yml",
  };
  const boundRun = {
    attempt: args.attempt,
    createdAt: "2026-07-31T00:00:00Z",
    event: "pull_request_target",
    id: args.runId,
    pulls: [{ baseSha: args.baseSha, headSha: args.headSha, number: args.prNumber }],
    workflowId: "99",
  };
  const snapshotValue = {
    pr: { baseSha: args.baseSha, headRepository: args.repository, headSha: args.headSha, number: args.prNumber, state: "open" },
    repository: { fullName: args.repository },
    run: boundRun,
    workflow: { id: "99", path: args.workflowPath },
    workflowRuns: [boundRun],
  };
  return { args, boundRun, snapshotValue };
}

function statusResponse(input, overrides = {}) {
  return {
    context: input.context,
    creator: { id: 15368 },
    state: input.state,
    target_url: input.targetUrl,
    url: `https://api.github.com/repos/${input.repository}/statuses/${input.headSha}`,
    ...overrides,
  };
}

function releaseTagMessage(value, manifest) {
  return [
    `Netlist Studio v${value.version}`,
    "",
    "Release-Schema: netlist-studio.formal-release-tag/v1",
    `Version: ${value.version}`,
    "Repository: y-asami3534/netlist-studio-releases",
    "Source-Repository: y-asami3534/netlist-studio",
    `Source-Commit: ${value.source.commit}`,
    `DMG-SHA256: ${manifest.artifacts[0].sha256}`,
    `ZIP-SHA256: ${manifest.artifacts[1].sha256}`,
    `Evidence-SHA256: ${manifest.evidence.sha256}`,
    `Release-Owner: ${manifest.approval.releaseOwner}`,
    "Approval: approved",
    "Signing-Key-Fingerprint: SHA256:byJQrGJp2En8bA2tWQcD73wnEnJRGjSz7tpRwoJWA4w",
    releaseTagSignature,
  ].join("\n");
}

function providerTarget(integrationId = 15368) {
  return {
    actions: { allowedActions: "all", enabled: true, shaPinningRequired: true },
    branch: "main",
    merge: { allowAutoMerge: false, allowMergeCommit: true, allowRebaseMerge: false, allowSquashMerge: false, deleteBranchOnMerge: true },
    ruleset: {
      allowBypass: false,
      allowDeletion: false,
      allowForcePush: false,
      conversationResolutionRequired: true,
      enforcement: "active",
      mergeMethods: ["merge"],
      name: "protect-main",
      requiredApprovals: 0,
      requiredChecks: [
        { context: "channel-data", integrationId },
        { context: "trusted-policy", integrationId },
      ],
      requiredSignatures: true,
      strictRequiredChecks: true,
    },
    workflow: { canApprovePullRequestReviews: false, defaultWorkflowPermissions: "read" },
  };
}

function providerEvidence() {
  const request = {
    exceptionId: policy.providerException.exceptionId,
    repository: { branch: "main", fullName: policy.repositories.release.fullName, id: policy.repositories.release.id },
    rollbackSnapshot: { sha256: "f".repeat(64), storage: "external-ephemeral" },
    schema: "netlist-studio.provider-policy-request",
    schemaVersion: 1,
    target: providerTarget(),
  };
  const requestText = canonicalJson(request);
  const readback = {
    checkSources: [
      { attempt: 1, context: "channel-data", headSha: "a".repeat(40), integrationId: 15368, runId: 100, slug: "github-actions" },
      { attempt: 1, context: "trusted-policy", headSha: "a".repeat(40), integrationId: 15368, runId: 101, slug: "github-actions" },
    ],
    exceptionId: policy.providerException.exceptionId,
    observedAt: "2026-08-01T01:02:03Z",
    repositoryId: policy.repositories.release.id,
    requestSha256: createHash("sha256").update(requestText).digest("hex"),
    rulesetId: 99,
    schema: "netlist-studio.provider-policy-readback",
    schemaVersion: 1,
    target: providerTarget(),
  };
  return { readback, request, requestText };
}

test("configuration fixes data-only zones and the approved personal-repo exception", () => {
  assert.doesNotThrow(() => validateConfiguration(contract, policy));
  assert.equal(contract.trustZones["source-ci"].executesCandidate, false);
  assert.equal(contract.trustZones["source-ci"].candidateMode, "git-data-only");
  assert.deepEqual(contract.providerInvariants.requiredCheckNames, ["channel-data", "trusted-policy"]);
  assert.equal(contract.providerInvariants.requiredWorkflowGate.mode, "approved-personal-repository-exception");
  assert.equal(policy.providerException.approved, true);
});

test("strict JSON rejects duplicate keys and canonical JSON is deterministic", () => {
  assert.throws(() => parseJsonStrict('{"a":1,"a":2}\n'), /duplicate JSON key/u);
  assert.equal(canonicalJson({ z: 1, a: { y: 2, b: 3 } }), '{\n  "a": {\n    "b": 3,\n    "y": 2\n  },\n  "z": 1\n}\n');
});

test("change classifier permits bootstrap, exact data classes, and isolated policy maintenance", () => {
  assert.equal(classifyChangedPaths(policy.bootstrap.requiredPaths, { baseHasPolicy: false, baseSha: policy.bootstrap.baseCommit, policy }), "policy-bootstrap");
  assert.throws(() => classifyChangedPaths(policy.bootstrap.requiredPaths, { baseHasPolicy: false, baseSha: "0".repeat(40), policy }), /bootstrap base commit/u);
  assert.equal(classifyChangedPaths(policy.changeClasses["provider-policy"], { baseHasPolicy: true, baseSha: policy.bootstrap.baseCommit, policy }), "provider-policy");
  assert.equal(classifyChangedPaths(["pipeline.contract.json"], { baseHasPolicy: true, baseSha: policy.bootstrap.baseCommit, policy }), "policy-maintenance");
  assert.throws(() => classifyChangedPaths(["release-manifest.json", ...policy.changeClasses["stable-channel"]], { baseHasPolicy: true, baseSha: policy.bootstrap.baseCommit, policy }), /mixed or incomplete/u);
  assert.throws(() => classifyChangedPaths(["SECURITY.md", "release-manifest.json"], { baseHasPolicy: true, baseSha: policy.bootstrap.baseCommit, policy }), /mixed or incomplete/u);
});

test("repository snapshot rejects unknown, symlink, and oversized entries", async () => {
  const unknownRoot = await mkdtemp(path.join(os.tmpdir(), "channel-policy-unknown-"));
  roots.push(unknownRoot);
  await writeFile(path.join(unknownRoot, "unknown.txt"), "x");
  await assert.rejects(readRepositorySnapshot(unknownRoot, policy), /unexpected repository path/u);

  const symlinkRoot = await mkdtemp(path.join(os.tmpdir(), "channel-policy-link-"));
  roots.push(symlinkRoot);
  await writeFile(path.join(symlinkRoot, "target"), "x");
  await symlink("target", path.join(symlinkRoot, "README.md"));
  await assert.rejects(readRepositorySnapshot(symlinkRoot, policy), /symlink is forbidden/u);

  const oversizedRoot = await mkdtemp(path.join(os.tmpdir(), "channel-policy-size-"));
  roots.push(oversizedRoot);
  await writeFile(path.join(oversizedRoot, "README.md"), "x".repeat(9));
  await assert.rejects(readRepositorySnapshot(oversizedRoot, { ...policy, limits: { ...policy.limits, maximumFileBytes: 8 } }), /oversized/u);
});

test("policy maintenance validates candidate policy as data without mixing release content", async () => {
  const base = await readRepositorySnapshot(repositoryRoot, policy);
  const candidate = cloneSnapshot(base);
  candidate.files.set("SECURITY.md", Buffer.concat([candidate.files.get("SECURITY.md"), Buffer.from("\n") ]));
  const result = await validateChange({ base, candidate, baseSha: "a".repeat(40), contract, policy });
  assert.equal(result.classification, "policy-maintenance");
  assert.equal(result.details.classification, "policy-maintenance");
  assert.equal(validatePolicyMaintenance({ candidate, contract, policy }).classification, "policy-maintenance");

  const mixed = cloneSnapshot(candidate);
  mixed.files.set("release-manifest.json", Buffer.from(`${JSON.stringify(releaseManifest("0.40.1"), null, 2)}\n`));
  await assert.rejects(validateChange({ base, candidate: mixed, baseSha: "a".repeat(40), contract, policy }), /mixed or incomplete/u);
});

test("policy maintenance rejects missing protected files and self-expanded boundaries", async () => {
  const base = await readRepositorySnapshot(repositoryRoot, policy);
  const missing = cloneSnapshot(base);
  missing.files.delete(".secure-ci-cd/policy-cli.mjs");
  await assert.rejects(validateChange({ base, candidate: missing, baseSha: "a".repeat(40), contract, policy }), /missing protected path/u);

  const expanded = cloneSnapshot(base);
  const expandedPolicy = structuredClone(policy);
  expandedPolicy.changeClasses["policy-maintenance"].push("untrusted.mjs");
  expanded.files.set("channel-policy.json", Buffer.from(canonicalJson(expandedPolicy)));
  await assert.rejects(validateChange({ base, candidate: expanded, baseSha: "a".repeat(40), contract, policy }), /path set|protected path boundary/u);
});

test("policy maintenance cannot authorize candidate-selected Action SHAs", async () => {
  const base = await readRepositorySnapshot(repositoryRoot, policy);
  const candidate = cloneSnapshot(base);
  const candidateContract = structuredClone(contract);
  const previousSha = candidateContract.toolchain.actions.checkout.commitSha;
  const candidateSha = "f".repeat(40);
  candidateContract.toolchain.actions.checkout.commitSha = candidateSha;
  candidate.files.set("pipeline.contract.json", Buffer.from(canonicalJson(candidateContract)));
  for (const relativePath of [
    ".github/workflows/channel-promotion-evidence.yml",
    ".github/workflows/channel-source-ci.yml",
    ".github/workflows/channel-trusted-policy.yml",
  ]) {
    const workflow = candidate.files.get(relativePath).toString("utf8").replaceAll(previousSha, candidateSha);
    candidate.files.set(relativePath, Buffer.from(workflow));
  }
  await assert.rejects(validateChange({ base, candidate, baseSha: "a".repeat(40), contract, policy }), /authority-bearing configuration/u);
});

test("trusted workflow permissions keep candidate validation read-only", async () => {
  const workflowPath = path.join(repositoryRoot, ".github/workflows/channel-trusted-policy.yml");
  const text = await readFile(workflowPath, "utf8");
  assert.doesNotThrow(() => validateWorkflowText(text, "trusted-policy", contract));

  const workflowWrite = text.replace("permissions: {}", "permissions:\n  statuses: write");
  assert.throws(() => validateWorkflowText(workflowWrite, "trusted-policy", contract), /permission scopes|least-privilege/u);

  const validatorWrite = text.replace("  validate-candidate-data:\n    name: validate-candidate-data\n    needs:\n      - initialize-trusted-status\n    permissions:\n      contents: read", "  validate-candidate-data:\n    name: validate-candidate-data\n    needs:\n      - initialize-trusted-status\n    permissions:\n      contents: read\n      statuses: write");
  assert.notEqual(validatorWrite, text);
  assert.throws(() => validateWorkflowText(validatorWrite, "trusted-policy", contract), /validator permissions/u);

  const missingPublisherRead = text.replace("  publish-trusted-status:\n    name: publish-trusted-status\n    if: ${{ always() }}\n    needs:\n      - initialize-trusted-status\n      - validate-candidate-data\n    permissions:\n      actions: read", "  publish-trusted-status:\n    name: publish-trusted-status\n    if: ${{ always() }}\n    needs:\n      - initialize-trusted-status\n      - validate-candidate-data\n    permissions:");
  assert.notEqual(missingPublisherRead, text);
  assert.throws(() => validateWorkflowText(missingPublisherRead, "trusted-policy", contract), /publisher permissions|permissions block/u);

  const base = await readRepositorySnapshot(repositoryRoot, policy);
  const candidate = cloneSnapshot(base);
  candidate.files.set(".github/workflows/channel-trusted-policy.yml", Buffer.from(validatorWrite));
  await assert.rejects(validateChange({ base, candidate, baseSha: "a".repeat(40), contract, policy }), /validator permissions/u);
});

test("initial channel accepts the exact pair and rejects metadata, URL, key, and version drift", () => {
  const validBinding = binding();
  const bindingText = `${JSON.stringify(validBinding, null, 2)}\n`;
  const parsed = parseChannelBinding(bindingText, policy);
  const base = snapshot({ "release-manifest.json": `${JSON.stringify(releaseManifest("0.39.23"), null, 2)}\n` });
  const candidate = snapshot({
    "release-manifest.json": `${JSON.stringify(releaseManifest(), null, 2)}\n`,
    "channels/stable/macos/arm64/channel-binding.json": bindingText,
    "channels/stable/macos/arm64/latest-mac.yml": expectedLatestMac(parsed),
  });
  assert.equal(validateStableChannelSnapshot({ base, candidate, policy }).binding.version, "0.40.0");

  const metadataDrift = snapshot(Object.fromEntries([...candidate.files].map(([name, bytes]) => [name, bytes.toString("utf8")] )));
  metadataDrift.files.set("channels/stable/macos/arm64/latest-mac.yml", Buffer.from(`${expectedLatestMac(parsed)}extra: true\n`));
  assert.throws(() => validateStableChannelSnapshot({ base, candidate: metadataDrift, policy }), /does not exactly match/u);

  const relative = binding();
  relative.assets[0].url = "Netlist-Studio-0.40.0-arm64.zip";
  assert.throws(() => parseChannelBinding(`${JSON.stringify(relative, null, 2)}\n`, policy), /URL must be/u);

  const unknown = { ...binding(), extra: true };
  assert.throws(() => parseChannelBinding(`${JSON.stringify(unknown, null, 2)}\n`, policy), /keys must be exactly/u);

  assert.throws(() => parseChannelBinding(`${JSON.stringify(binding({ previousVersion: "0.40.0" }), null, 2)}\n`, policy), /must increase/u);
  const wrongInitial = binding({ version: "0.40.1", previousVersion: "0.39.23" });
  const wrongParsed = parseChannelBinding(`${JSON.stringify(wrongInitial, null, 2)}\n`, policy);
  const wrongCandidate = snapshot({
    "release-manifest.json": `${JSON.stringify(releaseManifest("0.40.1"), null, 2)}\n`,
    "channels/stable/macos/arm64/channel-binding.json": `${JSON.stringify(wrongInitial, null, 2)}\n`,
    "channels/stable/macos/arm64/latest-mac.yml": expectedLatestMac(wrongParsed),
  });
  assert.throws(() => validateStableChannelSnapshot({ base, candidate: wrongCandidate, policy }), /initial stable channel version pair/u);
});

test("release manifest update must be a strict stable SemVer increase", () => {
  const base = snapshot({ "release-manifest.json": `${JSON.stringify(releaseManifest("0.40.0"), null, 2)}\n` });
  const candidate = snapshot({ "release-manifest.json": `${JSON.stringify(releaseManifest("0.40.1"), null, 2)}\n` });
  assert.equal(validateReleaseManifestUpdate({ base, candidate, policy }).next.version, "0.40.1");
  assert.throws(() => validateReleaseManifestUpdate({ base, candidate: snapshot({ "release-manifest.json": `${JSON.stringify(releaseManifest("0.39.99"), null, 2)}\n` }), policy }), /strictly increase/u);
});

test("provider policy remains held until canonical request and matching read-back are both present", () => {
  const { readback, request, requestText } = providerEvidence();
  assert.throws(() => validateProviderFiles(snapshot({ "provider-policy.request.json": requestText }), policy), /both required/u);
  const valid = snapshot({
    "provider-policy.request.json": requestText,
    "provider-policy.readback.json": canonicalJson(readback),
  });
  assert.equal(validateProviderFiles(valid, policy).classification, "provider-policy");
  const drifted = structuredClone(readback);
  drifted.target.ruleset.requiredChecks[1].integrationId = 1;
  assert.throws(() => validateProviderFiles(snapshot({ "provider-policy.request.json": canonicalJson(request), "provider-policy.readback.json": canonicalJson(drifted) }), policy), /one GitHub Actions integration|does not match/u);
});

test("remote release evidence binds immutable release assets and byte-identical manifests", () => {
  const manifest = releaseManifest();
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  const value = binding();
  value.manifest.sha256 = createHash("sha256").update(manifestBytes).digest("hex");
  value.manifest.size = manifestBytes.length;
  const releaseAssets = [
    ...value.assets.map((asset) => ({ browser_download_url: asset.url, digest: `sha256:${asset.sha256}`, id: asset.id, name: asset.name, size: asset.size, state: "uploaded" })),
    { browser_download_url: `https://github.com/y-asami3534/netlist-studio-releases/releases/download/v0.40.0/release-manifest.json`, digest: `sha256:${value.manifest.sha256}`, id: value.manifest.id, name: "release-manifest.json", size: value.manifest.size, state: "uploaded" },
  ];
  const remote = {
    latestReleaseId: 1,
    release: { assets: releaseAssets, draft: false, id: value.release.id, immutable: true, prerelease: false, published_at: value.release.publishedAt, tag_name: value.release.tag },
    releaseManifestAssetBytes: manifestBytes,
    taggedManifestBytes: manifestBytes,
    tagObject: {
      message: releaseTagMessage(value, manifest),
      object: { sha: value.release.tagTarget, type: "commit" },
      sha: value.release.tagObject,
      tag: value.release.tag,
      tagger: { email: policy.releaseTag.signingPrincipal, name: manifest.approval.releaseOwner },
      verification: { reason: "valid", signature: releaseTagSignature, verified: true },
    },
    tagRef: { object: { sha: value.release.tagObject, type: "tag" }, ref: `refs/tags/${value.release.tag}` },
  };
  assert.equal(validateRemoteReleaseSnapshot({ binding: value, candidateManifestBytes: manifestBytes, policy, snapshot: remote }).releaseId, value.release.id);
  assert.throws(() => validateRemoteReleaseSnapshot({ binding: value, candidateManifestBytes: manifestBytes, policy, snapshot: { ...remote, latestReleaseId: value.release.id } }), /must not become GitHub Latest/u);
  const unsigned = structuredClone(remote);
  unsigned.releaseManifestAssetBytes = manifestBytes;
  unsigned.taggedManifestBytes = manifestBytes;
  unsigned.tagObject.verification.verified = false;
  assert.throws(() => validateRemoteReleaseSnapshot({ binding: value, candidateManifestBytes: manifestBytes, policy, snapshot: unsigned }), /verified annotated tag/u);
});

test("trusted publication performs fresh verification before and after one status POST", async () => {
  const { args, snapshotValue } = publicationFixture();
  const sequence = [];
  const result = await publishTrustedStatus(args, {
    collect: async (input) => {
      sequence.push("verify");
      return validatePublicationSnapshot(structuredClone(snapshotValue), input);
    },
    createStatus: async (input) => {
      sequence.push(`status:${input.state}`);
      return statusResponse(input);
    },
  });
  assert.equal(result.publication, "PASS");
  assert.deepEqual(sequence, ["verify", "status:success", "verify"]);
});

test("trusted publication invalidates success after base, head, run, or attempt drift", async () => {
  const scenarios = [
    ["base", (snapshotValue) => { snapshotValue.pr.baseSha = "3".repeat(40); }],
    ["head", (snapshotValue) => { snapshotValue.pr.headSha = "4".repeat(40); }],
    ["newer run", (snapshotValue, boundRun) => { snapshotValue.workflowRuns.push({ ...boundRun, createdAt: "2026-07-31T00:01:00Z", id: "11" }); }],
    ["attempt", (snapshotValue) => { snapshotValue.run.attempt = "2"; }],
  ];
  for (const [name, mutate] of scenarios) {
    const { args, boundRun, snapshotValue } = publicationFixture();
    const postSnapshot = structuredClone(snapshotValue);
    mutate(postSnapshot, boundRun);
    const snapshots = [snapshotValue, postSnapshot];
    const states = [];
    await assert.rejects(publishTrustedStatus(args, {
      collect: async (input) => validatePublicationSnapshot(structuredClone(snapshots.shift()), input),
      createStatus: async (input) => {
        states.push(input.state);
        return statusResponse(input);
      },
    }), undefined, name);
    assert.deepEqual(states, ["success", "failure"], name);
  }
});

test("trusted publication rejects response binding drift and overwrites possible success", async () => {
  const responseDrifts = [
    ["sha", { url: `https://api.github.com/repos/y-asami3534/netlist-studio-releases/statuses/${"9".repeat(40)}` }],
    ["context", { context: "other" }],
    ["state", { state: "pending" }],
    ["target URL", { target_url: "https://github.com/other" }],
  ];
  for (const [name, overrides] of responseDrifts) {
    const { args, snapshotValue } = publicationFixture();
    const states = [];
    await assert.rejects(publishTrustedStatus(args, {
      collect: async (input) => validatePublicationSnapshot(structuredClone(snapshotValue), input),
      createStatus: async (input) => {
        states.push(input.state);
        return states.length === 1 ? statusResponse(input, overrides) : statusResponse(input);
      },
    }), /status response binding/u, name);
    assert.deepEqual(states, ["success", "failure"], name);
  }
});

test("trusted publication never returns PASS when stale success cannot be invalidated", async () => {
  const { args, snapshotValue } = publicationFixture();
  let statusCount = 0;
  await assert.rejects(publishTrustedStatus(args, {
    collect: async (input) => {
      if (statusCount === 0) return validatePublicationSnapshot(structuredClone(snapshotValue), input);
      throw new PolicyViolation("current pull request binding changed");
    },
    createStatus: async (input) => {
      statusCount += 1;
      return statusCount === 1 ? statusResponse(input) : statusResponse(input, { context: "other" });
    },
  }), /could not be invalidated/u);
  assert.equal(statusCount, 2);
});

test("trusted status response validation binds exact SHA, context, state, and target URL", () => {
  const { args } = publicationFixture();
  assert.equal(validateStatusResponse(statusResponse(args), args).state, "success");
  assert.throws(() => validateStatusResponse(statusResponse(args, { url: `https://api.github.com/repos/${args.repository}/statuses/${"0".repeat(40)}` }), args), /binding changed/u);
});

test("CLI preserves exit code 2 for usage and errors expose policy code 1", () => {
  assert.equal(new PolicyViolation("x").exitCode, 1);
  assert.equal(new UsageError("x").exitCode, 2);
  const result = spawnSync(process.execPath, [path.join(repositoryRoot, ".secure-ci-cd/policy-cli.mjs"), "unknown-command"], { encoding: "utf8" });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /UsageError/u);
  const pipeline = spawnSync(process.execPath, [path.join(repositoryRoot, ".secure-ci-cd/policy-cli.mjs"), "validate-pipeline", "--root", repositoryRoot, "--contract", path.join(repositoryRoot, "pipeline.contract.json"), "--policy", path.join(repositoryRoot, "channel-policy.json")], { encoding: "utf8" });
  assert.equal(pipeline.status, 0, pipeline.stderr);
  assert.match(pipeline.stdout, /"status": "PASS"/u);
});

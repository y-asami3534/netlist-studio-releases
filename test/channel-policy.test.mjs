import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
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
  validateProviderFiles,
  validateReleaseManifestUpdate,
  validateRemoteReleaseSnapshot,
  validateStableChannelSnapshot,
} from "../.secure-ci-cd/policy-lib.mjs";
import { validatePublicationSnapshot } from "../.secure-ci-cd/verify-trusted-publication.mjs";

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

test("change classifier permits the one-time exact bootstrap and exact provider class only", () => {
  assert.equal(classifyChangedPaths(policy.bootstrap.requiredPaths, { baseHasPolicy: false, baseSha: policy.bootstrap.baseCommit, policy }), "policy-bootstrap");
  assert.throws(() => classifyChangedPaths(policy.bootstrap.requiredPaths, { baseHasPolicy: false, baseSha: "0".repeat(40), policy }), /bootstrap base commit/u);
  assert.equal(classifyChangedPaths(policy.changeClasses["provider-policy"], { baseHasPolicy: true, baseSha: policy.bootstrap.baseCommit, policy }), "provider-policy");
  assert.throws(() => classifyChangedPaths(["pipeline.contract.json"], { baseHasPolicy: true, baseSha: policy.bootstrap.baseCommit, policy }), /immutable after bootstrap/u);
  assert.throws(() => classifyChangedPaths(["release-manifest.json", ...policy.changeClasses["stable-channel"]], { baseHasPolicy: true, baseSha: policy.bootstrap.baseCommit, policy }), /mixed or incomplete/u);
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

test("trusted publication rejects a stale successful run", () => {
  const args = { repository: "y-asami3534/netlist-studio-releases", workflowPath: ".github/workflows/channel-trusted-policy.yml", prNumber: "7", baseSha: "1".repeat(40), headSha: "2".repeat(40), runId: "10", attempt: "1" };
  const boundRun = { id: "10", attempt: "1", event: "pull_request_target", workflowId: "99", createdAt: "2026-07-31T00:00:00Z", pulls: [{ number: "7", baseSha: args.baseSha, headSha: args.headSha }] };
  const snapshotValue = { repository: { fullName: args.repository }, pr: { number: "7", state: "open", baseSha: args.baseSha, headSha: args.headSha, headRepository: args.repository }, workflow: { id: "99", path: args.workflowPath }, run: boundRun, workflowRuns: [boundRun] };
  assert.equal(validatePublicationSnapshot(snapshotValue, args).status, "PASS");
  snapshotValue.workflowRuns.push({ ...boundRun, id: "11", createdAt: "2026-07-31T00:01:00Z" });
  assert.throws(() => validatePublicationSnapshot(snapshotValue, args), /superseded/u);
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

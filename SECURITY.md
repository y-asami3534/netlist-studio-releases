# Stable channel security policy

## Trust zones

stable channelの変更は、次の3つの信頼境界を分離します。

- `channel-source-ci`: `pull_request`上でdefault branchのvalidatorを実行し、candidateをGit dataとして読みます。secretとwrite permissionは使用しません。
- `channel-trusted-policy`: `pull_request_target`上でdefault branchのpolicyだけを実行し、current base/headとlatest run/attemptを照合した後に、exact headの`trusted-policy` statusだけを書きます。
- `channel-promotion-evidence`: 証拠をread-onlyで照合し、credentialを含まないreceiptを作るだけです。merge、tag、release、feed、provider設定は変更しません。

candidate側のworkflow、script、package、hookはtrusted zoneで実行しません。required contextは`channel-data`と`trusted-policy`の2件です。

## Approved personal-repository exception

GitHubのprovider-native required workflowはOrganizationまたはEnterprise所有repositoryでのみ利用できるため、個人所有の本repositoryでは次の例外を明示的に適用します。

- exception ID: `personal-repository-no-required-workflow-v1`
- strict required status checksを有効にする。
- required contextのsource appをexactなGitHub Actions integrationへ固定する。
- trusted workflow、contract、validatorのcandidate bytesをdefault branchと照合する。
- status公開の前後でcurrent PR base/headとlatest run/attemptを再照合する。
- bypass、force-push、main deletionを許可しない。

required workflowが防ぐrunner queue開始前のwindowを完全には代替できない残余riskは、承認済み例外として保持します。Organizationへ移管する場合は、別のpolicy work unitでrequired workflowへ移行します。

## One-time bootstrap exception

最初のpolicy PRに限り、default branchにtrusted workflowが存在せず自己保護できません。この例外は次の値へ固定します。

- release repository base: `db9a9a6166b5b94043a930bbc73633b27dc42b8f`
- upstream app prerequisite: `da271f765fd8ccd5985e9959e53614768bb15396`
- bootstrap PRにstable channel fileを含めない。
- local validator test、workflow静的監査、topic commit署名、2-parent mergeとprovider署名をread-backする。
- bootstrap merge後に同じbaseや例外を再利用しない。

## Provider hold

`provider-policy-readback`は現在のexternal holdです。active ruleset、strict required checks、source app identity、merge-only設定、署名必須、bypass不在をAPIでread-backし、canonical receiptがdefault branchに含まれるまでstable channelのpromotionを許可しません。

provider設定とread-backが一致しない場合は、古い成功runや手動判定で迂回せず`HOLD`とします。

## Provider protection work unit

provider保護は`main@35853bd54956f805c5e0eaf42d7943be3b9a55a2`をDirect-Baseとする独立PRで固定します。個人所有repositoryのためorganization-level required workflowを利用できない点は、`personal-repository-no-required-workflow-v1`として承認済みの残余riskです。

適用前にallowlist形式のrollback snapshotをmode `0700`の外部一時directoryへ保存します。設定はmerge commitのみ、署名必須、strictな`channel-data`／`trusted-policy`、conversation resolution、bypassなし、force-push／deletion禁止、workflow token read-only、Actions full-SHA pinningを正本とします。

required contextは、このPRのexact headに発行されたGitHub Actions integration identityへ束縛します。設定後はAPI read-backをcanonical receiptとして同PRへ追加し、新しいexact headで両contextが成功した場合だけ2-parent mergeします。不一致時はrollbackして`HOLD`します。

# netlist-studio-releases

Netlist Studioの署名済みrelease artifactと、macOS stable update channelの公開用repositoryです。

## macOS stable channel

- feed: `channels/stable/macos/arm64/`
- metadata: `latest-mac.yml`
- provenance: `channel-binding.json`
- GitHub Latestはstable channelの正本として使用しません。

rolling `release-manifest.json`はchannelへ昇格できるversionの上限です。各channel targetの正本は、現行`main`に含まれる署名済みannotated tag上のmanifestと、immutable GitHub Release assetとして公開された同一bytesのmanifestです。source identityとZIP／DMGのdigest・sizeはこのmanifestへ束縛します。

stable channelは正式な`0.40.0`を初期versionとして別PRで追加し、その後は`previousVersion`からstrictに単調増加させます。policy bootstrapとprovider保護の完了前は、channel fileを追加しません。

CIの信頼境界、個人所有repository例外、provider read-backの条件は[SECURITY.md](SECURITY.md)を参照してください。

## v0.41.1 公開完了範囲（2026-08-12）

- `distribution-release: complete`
- `runtime-update-verified: passed`
- `GitHub Latest: 368758593/v0.41.1`

immutableなv0.41.1 Release本文に記載された4 journeyは、公開時点の検証計画であり、完了実績を表すものではありません。後発のRelease Owner判断とv0.41.1固有の実運用証拠により、macOS arm64 stableにおけるv0.40.1からv0.41.1への検出、download、apply、自動relaunch、および同一環境でのup-to-date確認をruntime PASSとして受理しました。source formal-closure mergeは`63245ba788ea562ef1d4f035b505f8a1809cb3c1`です。

実証範囲にclean v0.41.0、failed-cache recovery、Windows auto-updateは含みません。Windowsのlegacy download path `releases/latest/download/latest.yml`が404になることはaccepted limitationです。

この訂正はREADMEの状態説明だけであり、immutable Release本文、tag、3 assets、`release-manifest.json`、stable channelは変更していません。

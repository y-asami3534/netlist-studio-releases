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

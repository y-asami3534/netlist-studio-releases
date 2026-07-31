# netlist-studio-releases

Netlist Studioの署名済みrelease artifactと、macOS stable update channelの公開用repositoryです。

## macOS stable channel

- feed: `channels/stable/macos/arm64/`
- metadata: `latest-mac.yml`
- provenance: `channel-binding.json`
- GitHub Latestはstable channelの正本として使用しません。

stable channelは正式な`0.40.0`公開後に別PRで初期化します。policy bootstrapとprovider保護の完了前は、channel fileを追加しません。

CIの信頼境界、個人所有repository例外、provider read-backの条件は[SECURITY.md](SECURITY.md)を参照してください。

# TIP Security Rules — 2.1.0

一般的なセキュリティベースラインと、社会的に問題化した脅威に対する緊急点検を分離して配信します。初期配信は **OWASP Top 10:2025（10項目）** と **NICT A2B注意喚起（7項目）** です。公式情報の確認日: 2026-10-21。

| パック | チャネル | 用途 |
| --- | --- | --- |
| `owasp-top10-2025` | `baseline` | OWASPの10カテゴリを点検する定常レビュー |
| `nict-a2b-2026-10` | `emergency` | NICTの2026-10-13付A2B注意喚起に対応する緊急点検 |

これは当プロジェクトが公式資料に基づいて作成したチェックリストです。NICT・OWASPが提供・認定する診断ルールではありません。金融庁等の規制対応パックは、根拠資料と適用対象を特定したうえで追加します。

## 配信ファイル

- [dist/manifest.json](dist/manifest.json): パックID、バージョン、チャネル、必須フラグ、JSONファイルのSHA-256。
- `dist/<pack-id>.json` / `.yaml`: チャネル別ルール。`packs/*.yaml` が編集元です。
- [dist/rules.yaml](dist/rules.yaml): 提示いただいた `version / description / rules` 形式の統合版。緊急項目だけを適用する場合はパック別ファイルを使ってください。
- [schema.json](schema.json): 配信用パックのJSON Schema。

GitHub Rawからは `https://raw.githubusercontent.com/masahiroid/security-rules/main/dist/manifest.json` を起点に取得できます。JSONを受信したら、読み込む前にマニフェストのSHA-256と照合してください。ハッシュは改変・取り違えの検出用で、配信者の署名ではありません。配信元とmainへの変更権限を管理してください。

`v2.0.0` 等のタグをpushすると、GitHub Actionsが検証・再生成したファイルをGitHub Releaseに添付します。固定版はタグまたはRelease、緊急更新への追従はmainを参照します。

## ローカルで試す

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python scripts/rules.py validate
.venv/bin/python scripts/rules.py build
.venv/bin/python -m unittest discover -s tests -v
```

### 緊急点検の証跡を作り、未確認をCIで止める

対象はサービスと環境の組み合わせで識別します。同じ証跡を別サービスに流用できないよう照合します。

```sh
mkdir -p security
.venv/bin/python scripts/rules.py init-evidence \
  --channel emergency --target example/service/production > security/evidence.json
# 各項目の点検を行い、security/evidence.jsonを編集する
.venv/bin/python scripts/rules.py check \
  --channel emergency --target example/service/production \
  --evidence security/evidence.json
```

初期状態はすべて`pending`で、チェックは終了コード1になります。各ルールの`check_steps`に沿ってレビューし、次を記録してください。

| フィールド | 内容 |
| --- | --- |
| `status` | `pass`、または根拠のある`not_applicable`。`pending`や`fail`は不通過 |
| `evidence` | 試験結果・ログ調査報告・設定レビュー等の参照先の配列。最低1件必須 |
| `reviewer` | レビュー担当者。必須 |
| `checked_at` | タイムゾーン付きISO日時。例: `2026-10-21T19:00:00+09:00`。未来・30日超過は不通過 |
| `reason` | `not_applicable`の場合の適用外理由。必須 |
| `pack_version` / `rule_sha256` | 初期生成時の値。現在の配信と異なる場合は再点検が必要 |

`--channel emergency`は新しく追加される緊急パックも対象にします。`--channel baseline`や`--pack owasp-top10-2025`で定常レビューを独立運用できます。指定を省略すると両パックを確認します。ルール内容を変えるとハッシュが変わり、バージョンを更新するとそのパックの既存証跡が無効になります。

証跡の内容やレビュー担当者の本人性、リンク先の実在はこのCLIでは検証しません。証跡ファイルとワークフローをCODEOWNERS等でセキュリティ担当者の承認対象にしてください。ログそのものや機密情報はコミットせず、アクセス制御された保管先への参照を記録します。

### コード上の候補検出

```sh
.venv/bin/python scripts/rules.py scan --channel emergency \
  --source /path/to/application > scan-results.json
```

正規表現はTS/JSコードの要確認箇所を探す補助です。検出結果は常に`review_required`、全体は`unverified`とし、検出ゼロでも適合判定を出しません。`scan`の終了コード0は走査成功を意味します。CIの合否には`check`を使ってください。ログ監視設定、API認可、SSRF、侵害の有無を正規表現だけで判断することはできません。`exclude_pattern`によるファイル単位の抑制は設けていません。

## 決定論的な検出（`detect`）

ルールに `detect` を書くと、[Codes Doctor](https://github.com/masahiroid/codes-doctor-vscode) 7.0以降が正規表現ではなくデータフロー解析で判定します。外部入力（`req.query`、`$_GET` 等）が危険な処理に届く箇所だけを、入力元から到達先までの経路付きで示します。`detect` があるルールでは `pattern` は使われません（`pattern` は旧版と `scripts/rules.py scan` 向けに残せます）。

```yaml
  detect:
    type: taint                  # 現在はtaintのみ
    languages: [typescript, php] # typescriptはJavaScriptファイルも対象
    sinks:
    - builtin: SQL Injection     # 組み込みの危険な処理を使う
    - callee: repo\.find(?:One|ById)   # 独自の呼び出し（呼び出し名全体に一致する正規表現）
      argument: 0                # 調べる引数（省略時は全引数）
    sources:                     # 任意: 組み込みの入力元に追加
    - \bevent\.body\b
    sanitizers:                  # 任意: 通ると安全とみなす関数（呼び出し名全体に一致）
    - assertOwner
    builtin_sources: true        # 任意: falseで組み込みの入力元を使わない
```

| 項目 | 内容 |
| --- | --- |
| `builtin` | `SQL Injection`、`Command Injection`、`Code Injection`、`SSRF`、`Path Traversal`、`XSS` |
| `languages` | `typescript`、`javascript`、`php`、`python`、`go`、`java`、`csharp`、`rust`、`cpp`（Codes Doctor 7.0のセキュリティルール走査はTS/JSとPHPのみ） |
| 正規表現 | 300文字以内。`(a+)+` のような入れ子の量指定子は拒否されます |

判定は関数単位です。関数・ファイルをまたぐ流れは追跡しないため、「到達なし」は安全の証明になりません。認可不備（BOLA）のように「〜を通らずに」を判定する必要がある項目は、まだ `detect` で表現できません。誤検知の多い正規表現を付けず、点検手順だけで配信してください。

### 既存ルールの書き換え手順

1. `packs/*.yaml` の該当ルールに `detect` を追加する。組み込みの `builtin` で足りるかを先に確認する。
2. 誤検知の多い `pattern` は削除する（`pattern_semantics` も一緒に削除）。
3. パックの `version` と `scripts/rules.py` の `VERSION` を上げる。既存の証跡は再点検が必要になる。
4. `validate`、テスト、`build` を実行し、`packs/` と `dist/` を一緒にコミットする。
5. Codes Doctorの `codeDoctor.securityRules.sourceUrl` に `file:///…/dist/manifest.json` を設定し、公開前に手元のコードで結果を確認する。

## 全社への強制適用

[examples/consumer-check.yml](examples/consumer-check.yml)を各アプリの`.github/workflows/security-review.yml`へ配置します。対象IDは `${github.repository}/production` になるため、同じIDで証跡を生成してください。配信リポジトリが非公開の場合は読み取り用GitHub Appトークンも設定します。

1. 組織のRulesetsまたはブランチ保護で`security-review`を必須チェックに設定する。
2. 証跡とワークフロー、配信ルールの変更にセキュリティ担当者のレビューを必須にする。
3. 対象リポジトリの一覧を管理し、全対象へ導入する。未導入リポジトリには強制力が及ばない。
4. 緊急ルールをmainへ配信すると、利用側の次回CIで新ルールの証跡が必須になる。サンプルはPR・push・日次で実行する。

このリポジトリだけでは他リポジトリの保護設定や全社導入状況は変更しません。日次CIの失敗は既存デプロイを自動停止しません。リリースも強制する場合はデプロイジョブを`security-review`成功に依存させてください。

## 更新手順

1. 省庁・NICT等の公式注意喚起を読み、発行日・適用対象・出典URLを確認する。
2. 緊急項目は`packs/`に`channel: emergency`、`mandatory: true`で追加・更新する。既存パック変更時はその`version`を上げる。
3. 配信全体のバージョンを`scripts/rules.py`の`VERSION`で上げる。ルールごとに安定ID、点検手順、証跡要件、Excel列名を保つ。
4. `validate`、テスト、`build`を実行し、`packs/`と`dist/`を一緒にコミットする。
5. mainへ反映する。固定版の配布は全体バージョンと一致する`vX.Y.Z`タグをpushする。

注意喚起の自動収集・無審査でのルール化は実装していません。公式情報を人が確認し、短い手順で点検項目として配信する構成です。Excel列のマッピングは含みますが、Excelファイル生成は含みません。

## 出典

- [NICT公式発表（2026-10-13）](https://www1.nict.go.jp/press/2026/10/13-1.html)
- [NICT CYNEX / LETTICE 詳細注意喚起・PDFへのリンク](https://cynex.nict.go.jp/library/261013-01.html)
- [OWASP Top 10:2025](https://top10.owasp.org/2025/0x00_2025-Introduction/)

NICTの公表ページに基づき、侵害確認・脆弱性点検・暫定緩和を点検項目にしています。「2026年8月以降」の一律のログ調査期間や、金融庁の要請としての旧API禁止は、この初期版では根拠を確認できないため指定していません。詳細PDF内のIoCは転記・固定せず、点検時に原資料を確認します。

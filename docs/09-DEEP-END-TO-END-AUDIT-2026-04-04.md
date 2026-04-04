# Deep End-to-End Audit Report (Static, No Coding)

Tanggal audit: 2026-04-04  
Ruang lingkup: seluruh pipeline pada folder hanzantijudol  
Mode audit: static code and artifact audit only (tanpa coding, tanpa eksekusi perubahan)

## 0. Update Status (Fix Wave 1)

Status implementasi setelah eksekusi perbaikan cepat:
- F-01 fixed: resolver issue-flow pada workflow verify sudah dinormalisasi agar tidak salah indentasi.
- F-02 fixed: step appeal-upsert pada workflow verify sudah dipisah sebagai step valid dengan env/run block yang benar.
- F-03 fixed: gate pada workflow generate sudah dipisah menjadi preflight dan post-consolidation gate yang valid.
- F-04 mitigated: generate sekarang memblokir publish jika verify-hunt tidak selaras (count/timestamp mismatch).
- F-05 mitigated: generate dan verify sekarang memvalidasi `ai_enabled=true` sebelum melanjutkan publish.
- F-07 fixed: source calibration tanpa evidence sekarang dinetralkan (multiplier 1.0).
- F-08 fixed: baseline metadata model sudah disediakan di repository.
- F-09 improved: hunter sekarang mendukung mode hybrid parallel (A terisolasi, B-F paralel) untuk menekan bottleneck.
- F-06 deferred: fine-tuning transformer tidak dimasukkan ke GitHub Actions core pada wave ini karena effort/biaya runtime tinggi dan perlu dataset governance tambahan.
- F-10 fixed: issue parsing yang gagal domain sekarang tidak mematikan workflow; run di-skip aman + issue dikomentari instruksi format domain.
- F-11 fixed: telemetry source quality sekarang menampilkan coverage ratio, unattributed verified domains, dan warning list saat mapping lemah.
- F-12 mitigated: registry dispute sekarang di-upsert untuk issue flow domain_report maupun appeal sehingga siklus governance tercatat sejak awal.

## 1. Executive Summary

Status readiness saat ini: FAIL untuk klaim production-grade full automation.

Kesimpulan inti:
- Sistem sudah benar-benar mampu memproses banyak domain dalam satu run, bukan hanya 1 domain per jam.
- Migrasi dari fastText ke SentenceTransformer sudah terjadi secara implementasi.
- Namun, ada gap kritis pada integritas workflow YAML, konsistensi artifact end-to-end, dan jalur adaptive learning yang belum sampai fine-tuning model.
- Snapshot artifact saat ini menunjukkan pipeline state stale, verify tertinggal, dan output publik kosong meskipun hunter menemukan kandidat.

## 2. Jawaban Cepat Atas Skeptisisme Utama

### 2.1 Bisa proses puluhan domain sekali workflow atau cuma 1 per jam?

Bisa multi-domain sekali run.

Bukti:
- Scheduler hunt memang per 3 jam, bukan per 1 jam: [hanzantijudol/.github/workflows/hunt.yml](hanzantijudol/.github/workflows/hunt.yml#L5)
- Orchestrator hunt menjalankan method A-F lalu merge semua domain: [hanzantijudol/scripts/hunter.py](hanzantijudol/scripts/hunter.py#L1135), [hanzantijudol/scripts/hunter.py](hanzantijudol/scripts/hunter.py#L1137)
- Verifier memproses list domain paralel dengan gather: [hanzantijudol/scripts/verifier.py](hanzantijudol/scripts/verifier.py#L1301), [hanzantijudol/scripts/verifier.py](hanzantijudol/scripts/verifier.py#L1302)
- Snapshot kandidat merged menunjukkan jumlah >1: [hanzantijudol/data/candidates_merged.json](hanzantijudol/data/candidates_merged.json#L3)

Catatan:
- Method A-F dieksekusi berurutan (bukan paralel lintas-method), jadi throughput dipengaruhi timeout/network per method.

### 2.2 FastText sudah tidak dipakai dan diganti SentenceTransformer, valid?

Valid, migrasi sudah jelas.

Bukti:
- Dependency SentenceTransformer ada di requirements: [hanzantijudol/scripts/requirements.txt](hanzantijudol/scripts/requirements.txt#L6)
- Tidak ada dependency fastText di requirements (tidak ditemukan).
- Komentar migrasi eksplisit di verifier: [hanzantijudol/scripts/verifier.py](hanzantijudol/scripts/verifier.py#L8)

### 2.3 SentenceTransformer perlu training?

Jawaban presisi:
- Untuk baseline operasional: tidak wajib fine-tune, karena model pre-trained bisa langsung inference + hybrid heuristic.
- Untuk target production-grade self-adaptive yang kuat: perlu data feedback berkualitas dan sebaiknya ada tahap fine-tuning periodik (atau minimal calibration yang benar-benar tervalidasi).

Bukti implementasi saat ini:
- Retrain saat ini calibration-only, bukan fine-tuning bobot transformer: [hanzantijudol/scripts/retrain_model.py](hanzantijudol/scripts/retrain_model.py#L4), [hanzantijudol/scripts/retrain_model.py](hanzantijudol/scripts/retrain_model.py#L251)

## 3. End-to-End Architecture Integrity Check

### 3.1 Target flow

Hunt -> Verify -> Generate -> Notify -> (scheduled) Retrain

Referensi workflow:
- [hanzantijudol/.github/workflows/hunt.yml](hanzantijudol/.github/workflows/hunt.yml)
- [hanzantijudol/.github/workflows/verify.yml](hanzantijudol/.github/workflows/verify.yml)
- [hanzantijudol/.github/workflows/generate.yml](hanzantijudol/.github/workflows/generate.yml)
- [hanzantijudol/.github/workflows/notify.yml](hanzantijudol/.github/workflows/notify.yml)
- [hanzantijudol/.github/workflows/retrain-model.yml](hanzantijudol/.github/workflows/retrain-model.yml)

### 3.2 Snapshot runtime artifact saat audit

- candidates_merged: 17 domain, timestamp lebih baru: [hanzantijudol/data/candidates_merged.json](hanzantijudol/data/candidates_merged.json#L3)
- verified_domains: hanya 4 input, ai_enabled false, crawl_failures 4: [hanzantijudol/data/verified_domains.json](hanzantijudol/data/verified_domains.json#L3), [hanzantijudol/data/verified_domains.json](hanzantijudol/data/verified_domains.json#L15), [hanzantijudol/data/verified_domains.json](hanzantijudol/data/verified_domains.json#L29)
- pipeline_health stale karena verify_data_stale: [hanzantijudol/data/pipeline_health.json](hanzantijudol/data/pipeline_health.json#L4), [hanzantijudol/data/pipeline_health.json](hanzantijudol/data/pipeline_health.json#L7), [hanzantijudol/data/pipeline_health.json](hanzantijudol/data/pipeline_health.json#L14)
- blocklist total_domains 0 meski ada kandidat: [hanzantijudol/data/blocklist.json](hanzantijudol/data/blocklist.json#L12), [hanzantijudol/data/blocklist.json](hanzantijudol/data/blocklist.json#L189)

Interpretasi:
- Chain artifact tidak sinkron end-to-end pada snapshot ini.

## 4. Findings (Severity-Ranked)

## F-01 (CRITICAL) Verify workflow mengandung indikasi kuat salah indentasi pada Python heredoc resolver mode

Bukti:
- Potongan resolver issue flow dengan indentasi tidak konsisten: [hanzantijudol/.github/workflows/verify.yml](hanzantijudol/.github/workflows/verify.yml#L137), [hanzantijudol/.github/workflows/verify.yml](hanzantijudol/.github/workflows/verify.yml#L158), [hanzantijudol/.github/workflows/verify.yml](hanzantijudol/.github/workflows/verify.yml#L186)

Risiko:
- Dapat memicu runtime error pada step resolve (misalnya IndentationError), atau menghasilkan output mode/domain yang tidak valid.
- Jika step ini gagal, jalur single-report, appeal-state, dan downstream verify bisa gagal total.

Dampak bisnis:
- User report dari webhook/issue dapat tidak masuk jalur verifikasi dengan benar.

## F-02 (CRITICAL) Verify workflow step appeal-upsert terlihat salah struktur/indentasi sehingga berpotensi tidak dieksekusi sesuai niat

Bukti:
- Step marker berada pada struktur yang mencurigakan: [hanzantijudol/.github/workflows/verify.yml](hanzantijudol/.github/workflows/verify.yml#L231)
- Env untuk target appeal ada di blok yang sama: [hanzantijudol/.github/workflows/verify.yml](hanzantijudol/.github/workflows/verify.yml#L318), [hanzantijudol/.github/workflows/verify.yml](hanzantijudol/.github/workflows/verify.yml#L319)

Risiko:
- Domain appeal state tidak ter-upsert konsisten ke data appeals.
- Governance false-positive bisa drift dari real issue state.

## F-03 (CRITICAL) Generate workflow freshness gate tampak salah struktur (indikasi step parsing ambiguity)

Bukti:
- Ada step marker gate yang tampak nested tidak wajar setelah run consolidator: [hanzantijudol/.github/workflows/generate.yml](hanzantijudol/.github/workflows/generate.yml#L68)
- Heredoc gate berada pada blok tersebut: [hanzantijudol/.github/workflows/generate.yml](hanzantijudol/.github/workflows/generate.yml#L71)

Risiko:
- Freshness and alignment gate tidak berjalan sesuai niat.
- Publish bisa lanjut walau verify stale.

Data pendukung:
- Pipeline health stale: [hanzantijudol/data/pipeline_health.json](hanzantijudol/data/pipeline_health.json#L4)
- Alasan stale verify_data_stale: [hanzantijudol/data/pipeline_health.json](hanzantijudol/data/pipeline_health.json#L7)

## F-04 (CRITICAL) Artifact chain hunt->verify->generate tidak sinkron pada snapshot saat ini

Bukti:
- candidates_merged candidate_count 17: [hanzantijudol/data/candidates_merged.json](hanzantijudol/data/candidates_merged.json#L3)
- verified total_input 4 dan crawl_failures 4: [hanzantijudol/data/verified_domains.json](hanzantijudol/data/verified_domains.json#L3), [hanzantijudol/data/verified_domains.json](hanzantijudol/data/verified_domains.json#L15)
- blocklist active 0: [hanzantijudol/data/blocklist.json](hanzantijudol/data/blocklist.json#L12)

Risiko:
- Output publik tidak mencerminkan discovery terbaru.
- Kualitas proteksi nyata di lapangan menurun karena publish berdasarkan data lama/parsial.

## F-05 (HIGH) Runtime artifact menunjukkan AI disabled pada snapshot, bertentangan dengan target AI-required pipeline

Bukti:
- ai_enabled false di verified output: [hanzantijudol/data/verified_domains.json](hanzantijudol/data/verified_domains.json#L29)
- Workflow batch/single mengaktifkan require-ai: [hanzantijudol/.github/workflows/verify.yml](hanzantijudol/.github/workflows/verify.yml#L204), [hanzantijudol/.github/workflows/verify.yml](hanzantijudol/.github/workflows/verify.yml#L221)

Interpretasi:
- Artifact kemungkinan berasal dari run lokal/test mode atau jalur lama, bukan jalur CI utama yang strict.

Risiko:
- Operator bisa salah menilai status sistem karena artifact campur antara strict CI dan local/test output.

## F-06 (HIGH) Klaim self-adaptive penuh belum tercapai karena retrain belum fine-tune model

Bukti:
- Retrain script menyatakan belum fine-tune bobot: [hanzantijudol/scripts/retrain_model.py](hanzantijudol/scripts/retrain_model.py#L4)
- Training mode calibration-only: [hanzantijudol/scripts/retrain_model.py](hanzantijudol/scripts/retrain_model.py#L251)

Risiko:
- Adaptasi terhadap drift pola judol hanya melalui threshold/multiplier, bukan representasi semantik model.
- Pada drift besar, precision/recall bisa drop lebih cepat.

## F-07 (HIGH) Source calibration artifact saat ini menunjukkan penalti 0.85 walau verified_count 0

Bukti:
- Multipliers 0.85 dengan verified_count 0: [hanzantijudol/data/source_calibration_profile.json](hanzantijudol/data/source_calibration_profile.json#L6), [hanzantijudol/data/source_calibration_profile.json](hanzantijudol/data/source_calibration_profile.json#L9)

Analisis:
- Ini bisa berasal dari artifact lama yang tidak sinkron dengan kode terbaru, atau jalur pembentukan profile yang tidak sesuai ekspektasi.

Risiko:
- Skor domain baru bisa teredam tanpa evidence memadai.

## F-08 (HIGH) Retrain workflow mengharuskan model metadata artifact, tetapi repository baseline belum memiliki artifact tersebut

Bukti:
- Workflow output ke model metadata: [hanzantijudol/.github/workflows/retrain-model.yml](hanzantijudol/.github/workflows/retrain-model.yml#L51)
- Workflow validasi file metadata: [hanzantijudol/.github/workflows/retrain-model.yml](hanzantijudol/.github/workflows/retrain-model.yml#L59)
- Folder models saat ini hanya menyimpan placeholder: [hanzantijudol/models/.gitkeep](hanzantijudol/models/.gitkeep)

Risiko:
- Jika jadwal retrain gagal satu kali, tidak ada fallback artifact yang siap untuk audit trail.

## F-09 (MEDIUM) Throughput lintas method hunt masih sequential, berpotensi bottleneck saat skala naik

Bukti:
- Eksekusi method A-F berurutan secara eksplisit: [hanzantijudol/scripts/hunter.py](hanzantijudol/scripts/hunter.py#L1136), [hanzantijudol/scripts/hunter.py](hanzantijudol/scripts/hunter.py#L1137)

Dampak:
- Puluhan domain masih realistis.
- Ratusan-ribuan dengan sumber berat bisa mendekati timeout workflow.

## F-10 (MEDIUM) Governance appeals masih sangat tergantung parsing domain dari issue body/title

Bukti:
- Domain parser regex issue flow: [hanzantijudol/.github/workflows/verify.yml](hanzantijudol/.github/workflows/verify.yml#L103)
- Jika mode single tanpa domain valid, run dihentikan: [hanzantijudol/.github/workflows/verify.yml](hanzantijudol/.github/workflows/verify.yml#L180)

Risiko:
- Labeling issue yang benar tapi format teks user buruk bisa menyebabkan proses gagal.

## F-11 (MEDIUM) Data quality matrix saat ini menunjukkan nol verifikasi per source walau ada candidate_total

Bukti:
- candidate_total ada, verified_count nol, source_yield nol: [hanzantijudol/data/source_quality_metrics.json](hanzantijudol/data/source_quality_metrics.json#L5), [hanzantijudol/data/source_quality_metrics.json](hanzantijudol/data/source_quality_metrics.json#L6), [hanzantijudol/data/source_quality_metrics.json](hanzantijudol/data/source_quality_metrics.json#L10)

Risiko:
- Adaptive source weighting menjadi tidak informatif.

## F-12 (LOW) Domain appeals dataset masih kosong sehingga jalur sengketa belum tervalidasi end-to-end pada artifact ini

Bukti:
- Appeals entries kosong: [hanzantijudol/data/domain_appeals.json](hanzantijudol/data/domain_appeals.json#L4)

Risiko:
- Tidak ada evidence publik bahwa siklus dispute sudah melewati kondisi riil.

## 5. Strengths (Yang Sudah Bagus)

## S-01 Require-AI gate di verifier workflow sudah ada

Bukti:
- Require AI batch/single: [hanzantijudol/.github/workflows/verify.yml](hanzantijudol/.github/workflows/verify.yml#L204), [hanzantijudol/.github/workflows/verify.yml](hanzantijudol/.github/workflows/verify.yml#L221)

## S-02 Verifier punya hard guard saat AI diwajibkan

Bukti:
- Raise error jika require-ai aktif tapi model unavailable: [hanzantijudol/scripts/verifier.py](hanzantijudol/scripts/verifier.py#L568), [hanzantijudol/scripts/verifier.py](hanzantijudol/scripts/verifier.py#L569)

## S-03 Webhook report sudah punya auth, rate-limit, dan dedupe

Bukti:
- Authorization check: [hanzantijudol/cloudflare-workers/report-webhook.js](hanzantijudol/cloudflare-workers/report-webhook.js#L105), [hanzantijudol/cloudflare-workers/report-webhook.js](hanzantijudol/cloudflare-workers/report-webhook.js#L211)
- Rate limit: [hanzantijudol/cloudflare-workers/report-webhook.js](hanzantijudol/cloudflare-workers/report-webhook.js#L50), [hanzantijudol/cloudflare-workers/report-webhook.js](hanzantijudol/cloudflare-workers/report-webhook.js#L233)
- Duplicate domain window: [hanzantijudol/cloudflare-workers/report-webhook.js](hanzantijudol/cloudflare-workers/report-webhook.js#L118), [hanzantijudol/cloudflare-workers/report-webhook.js](hanzantijudol/cloudflare-workers/report-webhook.js#L249)

## S-04 OCR second pass sudah diintegrasikan dengan trigger dinamis

Bukti:
- Trigger status/confidence: [hanzantijudol/scripts/verifier.py](hanzantijudol/scripts/verifier.py#L730), [hanzantijudol/scripts/verifier.py](hanzantijudol/scripts/verifier.py#L741)

## S-05 Dashboard publik sudah menyajikan data operasi yang kaya

Bukti:
- Build dashboard payload + static site: [hanzantijudol/scripts/build_pages_artifact.py](hanzantijudol/scripts/build_pages_artifact.py#L42), [hanzantijudol/scripts/build_pages_artifact.py](hanzantijudol/scripts/build_pages_artifact.py#L754)

## 6. Production-Grade Verdict Matrix

Data freshness:
- FAIL (verify stale pada artifact): [hanzantijudol/data/pipeline_health.json](hanzantijudol/data/pipeline_health.json#L4)

Workflow integrity:
- FAIL (indikasi kuat malformed indentation di verify/generate)

Model governance:
- PARTIAL (require-ai ada, retrain hanya calibration-only)

Appeals governance:
- PARTIAL (flow ada, namun dataset appeals kosong di snapshot)

Scalability:
- PARTIAL (multi-domain yes, tetapi hunt sequential lintas method)

Self-adaptive without manual calibration:
- FAIL (belum mencapai full closed-loop learning berbasis ground truth kuat)

## 7. Rekomendasi Fix Prioritas (Tanpa Ngoding di Dokumen Ini)

P0 (wajib sebelum klaim production-ready):
- Normalisasi struktur/indentasi [hanzantijudol/.github/workflows/verify.yml](hanzantijudol/.github/workflows/verify.yml) dan [hanzantijudol/.github/workflows/generate.yml](hanzantijudol/.github/workflows/generate.yml).
- Pastikan freshness gate dieksekusi sebagai step independen yang memblokir publish stale.
- Sinkronkan artifact chain supaya verify selalu merefleksikan candidates terbaru sebelum generate.

P1:
- Pisahkan artifact local/test dari artifact CI (nama file atau path terpisah) agar tidak merusak telemetry produksi.
- Stabilkan source calibration agar default tetap netral saat evidence belum cukup.

P2:
- Tambahkan quality acceptance gate minimum precision/false-positive threshold di jalur publish.
- Tambahkan validasi schema artifact dan timestamp monotonicity sebagai hard gate.

P3:
- Rancang fine-tuning pipeline SentenceTransformer berbasis feedback berkualitas (opsional tapi sangat dianjurkan untuk drift jangka panjang).

## 8. Keputusan Tentang Pertanyaan Training SentenceTransformer

Keputusan teknis:
- Tidak wajib training untuk memulai operasi jika require-ai, crawler, dan OCR berjalan stabil.
- Wajib direncanakan jika target adalah full-automation adaptif jangka panjang dengan kualitas tinggi pada drift cepat.

Pragmatis:
- Tahap 1: jalankan inference pre-trained + calibration threshold/source secara disiplin.
- Tahap 2: aktifkan fine-tuning periodik saat data feedback berkualitas sudah cukup.

## 9. Batasan Audit Ini

- Audit ini static (berdasarkan code dan artifact yang ada), tanpa melakukan perubahan kode.
- Karena tidak menjalankan validasi parser YAML linting/execution di sesi ini, temuan malformed indentation diklasifikasikan sebagai indikasi kuat berbasis struktur file saat dibaca.
- Meskipun begitu, evidence line-level menunjukkan risiko nyata yang tinggi untuk kegagalan runtime/logic.

## 10. Ringkasan Akhir

Kondisi saat ini belum memenuhi target sempurna 100% bug-free full automation production-grade.  
Fondasi arsitektur sudah kuat dan multi-domain capability nyata, tetapi ada gap kritis pada integritas workflow dan sinkronisasi artifact yang wajib ditutup dulu sebelum klaim siap produksi.

# GMM — klavye filtresi ve isim limiti teşhisi

Bu proje `libil2cpp.so` içinden `<size=...>` etiketinin silinmesi ve kullanıcı adı uzunluk kontrolüyle ilgili seçili fonksiyonları Ghidra ile çıkarır. Oyun dosyasını değiştirmez; `.so` mod üretmez. Çıkan C benzeri metin yaklaşık decompile çıktısıdır.

## GitHub'da çalıştırma

1. Bu ZIP'in içindeki proje dosyalarını kendi decompiler repona koy. **`.github/workflows/ghidra.yml` de dahil olmalı.** ZIP'i tek dosya olarak yüklemek workflow'u kurmaz. Eski araç analiz workflow'unu bu dosyayla değiştir.
2. Kullandığın oyunun **aynı sürümüne ait ARM32 / `armeabi-v7a/libil2cpp.so`** dosyasını **`input/libil2cpp.so`** adıyla koy.
3. **Önerilen:** APK'daki `assets/bin/Data/Managed/Metadata/global-metadata.dat` dosyasını **`input/global-metadata.dat`** olarak ekle. Yolu oyunun paket yapısına göre değişebilir. Regex kalıbı `.so` yerine bu dosyadaki string tablosunda tutulabilir; sadece `.so` ile tam kalıp her zaman bulunamaz.
4. **Actions → GMM Keyboard Filter Diagnostics → Run workflow** seç. İlk denemede `targeted` modunu kullan. Dosya değişikliklerini push etmek de otomatik başlatır.
5. İşlem bitince artifact **`gmm-keyboard-diagnostics`** ZIP'ini indirip gönder. Çalışma kırmızı olursa da artifact'i indir; hata günlükleri aynı ZIP'te tutulur.

Büyük `.so` dosyasını repona eklemek için Git LFS kullanabilirsin; `.gitattributes` ve checkout'un LFS desteği hazırdır. Repoda gerçek binary bulunmalı; LFS işaretçisi kontrol edilir. Oyun binary'sini herkese açık paylaşmak istemiyorsan özel repo kullan.

## Mimari ve sürüm uyumu

- Paketteki **51 metot girdisi**, daha önce sağlanan **ARM32 `dump.cs`** üzerinden seçildi. Filtre adlarını bulmak için binary'de sembollerin kalmış olması gerekmez.
- Bu adresler **aynı oyun build'i** için geçerlidir. ELF mimarisi ve adreslerin kod segmentinde olması kontrol edilir; bu kontroller sürüm eşleşmesini kanıtlamaz.
- **ARM64 veya başka oyun sürümü:** O binary'den üretilmiş doğru **`dump.cs`** dosyasını **`input/dump.cs`** olarak ekle. Akış, seçili sınıfların adreslerini yeni dump'tan alır. ARM64 binary'ye hazır ARM32 adresleri uygulanmaz; dump eksikse açık hata verir.
- `global-metadata.dat` dosyası da binary ile aynı build'den gelmeli. Sınıf adları da değişmişse hedef seçiminin ayrıca güncellenmesi gerekir. Bu akış metadata'dan yeni `dump.cs` üretmez ve şifreli metadata çözmez.
- Decompile çıktısı UI sahnesinde serialize edilmiş `characterLimit` değerini veya sunucu tarafındaki kontrolü tek başına göstermez. Buradaki hedef istemci metotları ve gerçek filtre kodudur.

## Hedeflenen kod

| Bölüm | Amaç |
|---|---|
| `TMPInputFieldTagFilter` | `Awake`, `OnDestroy`, `ggy`, `.cctor`: giriş filtresi, callback ve Regex kurulumu |
| `TMPTextTagFilter` | `ggz`, `.cctor`: görüntülenen metin filtresi ve Regex kurulumu |
| `ChangeUsernameManager` ve async `MoveNext` | İsim değiştirme butonu ve gönderim akışı |
| `fm`, `fm.<RequestAsync>d__2.MoveNext` | Dump'ta `3` ve `25` sabitleri bulunan isim isteği sınıfı; karşılaştırmaların incelenmesi |
| `playerNameManager`, `ChatMessage` | İsim alanı ve sohbet mesajı bağlantıları |
| Seçili `TMP_InputField` metotları | `SetText`, callback'ler, `characterLimit`, `Append`, `Validate`, gönderme/kapatma |

Seçilen fonksiyonların doğrudan çağırdığı ve mevcut analizde onları çağıran fonksiyonlar da **tek seviye**, sayı sınırıyla eklenir. Bütün IL2CPP motoru decompile edilmez. Adsız yardımcı fonksiyonların adları `FUN_...` kalabilir.

## Modlar ve çıktılar

**`targeted` (varsayılan):** Ghidra'nın bütün dosyayı otomatik analiz etmesini atlar. Bilinen adreslerde disassembly/fonksiyon oluşturur ve sınırlı komşuları çıkarır. Büyük dosyada ilk deneme için uygundur. Tüm çağıranlar/veri referansları bulunmayabilir.

**`full`:** Önce en çok 1800 saniyelik otomatik analiz çalıştırır, ardından aynı seçili çıkarımı yapar. Daha yavaştır; `targeted` çıktısında yetersiz referans varsa denenebilir. Analiz zaman aşımı logda görünür ve çıktı hâlâ eksik olabilir. İş toplam süresi en çok 120 dakikadır.

Artifact içeriği:

- `keyboard_decompiled.c`: seçili fonksiyonlar ve sınırlı komşuları.
- `keyboard_disassembly.txt`: aynı fonksiyonların assembly çıktısı.
- `keyboard_callgraph.tsv`: çözülebilen çağrı/akış referansları.
- `keyboard_data_refs.txt`: fonksiyonların referans verdiği veri ve pointer anlık görüntüleri.
- `length_constant_candidates.txt`: `3`, `25`, `1024` içeren operandlar. **Tek başlarına limit kanıtı değildir.**
- `metadata_literals.jsonl`: metadata eklendiyse `size`, `color`, kullanıcı adı ve uzunlukla ilgili aday string'ler. Literal indeksleri ve metadata ofsetleri korunur; native kullanımlara otomatik eşleme yapılmaz.
- `native_strings.jsonl`: `.so` içindeki sınırlı aday string'ler ve **dosya ofsetleri**; RVA değildir.
- `target_resolution.tsv`, `target_signatures.json`, `targets.tsv`: neyin hangi adreste arandığı/çözüldüğü.
- `input_report.json`: mimari, binary SHA-256, boyut ve kısıtlar.
- `summary.txt`, `headless_log.txt`: decompile sonuçları ve hatalar.
- `SUCCESS.json`: yalnızca çıkarım scripti bütün seçili seed'leri hatasız tamamladığında oluşur. Workflow, Java hatasını veya eksik sonucu başarılıymış gibi gizlemez.

Kaynaklar: [Ghidra 11.4.2](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_11.4.2_build), [Ghidra script API](https://ghidra.re/ghidra_docs/api/ghidra/app/script/GhidraScript.html), [decompiler API](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html).

## Doğrulama

Hazırlama scriptinin mimari, LFS işaretçisi, dump kapsamı, adres sınırı ve metadata string tablosu kontrolleri için 4 otomatik test bulunur (`python3 -m unittest discover -s tests -v`). Seçili çıkarım Ghidra 11.4.2 ile küçük ARM32 ve ARM64 deneme kütüphanelerinde denenmiştir; oyun binary'sindeki sonuçlar GitHub çalışmasından sonra incelenmelidir.

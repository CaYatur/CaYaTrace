<div align="center">

# CaYaTrace

**Windows uygulama adli analizi — bir programın sisteminizde ve ağda tam olarak ne yaptığını görün.**

[![Lisans: MIT](https://img.shields.io/badge/Lisans-MIT-dc2626.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-111826.svg)](#gereksinimler)
[![.NET](https://img.shields.io/badge/.NET-8.0-182438.svg)](#gereksinimler)
[![Durum](https://img.shields.io/badge/durum-0.1.0%20önizleme-b91c1c.svg)](docs/ROADMAP.md)

[English README](README.md) · [Mimari](docs/ARCHITECTURE.md) · [Güvenlik](SECURITY.md) · [Yol haritası](docs/ROADMAP.md)

</div>

---

> [!WARNING]
> **Yalnızca yetkili kullanım.** Kaydedilen oturumlar parolalar, oturum jetonları, çerezler,
> tam URL'ler, istek ve yanıt gövdeleri, dosya içerikleri ve kullanıcı adları gibi hassas
> veriler içerebilir. Bu aracı yalnızca size ait olan veya test etmek için açıkça yetkili
> olduğunuz sistemlerde kullanın. Bir oturumu asla herkese açık bir depoya yüklemeyin.
> Ayrıntılar: [SECURITY.md](SECURITY.md).

---

## Ne yapar

Kurulum izleyicileri size *neyin değiştiğini* gösterir. Ağ dinleyicileri *neyin
gönderildiğini* gösterir. CaYaTrace ikisini tek bir nedensel zincirde birleştirir; böylece
bir çift tıklamadan bir HTTPS isteğine kadar tek bir izi takip edebilirsiniz:

```
setup.exe
├─ msiexec.exe
│   ├─ FILE CREATE
│   │   └─ %PROGRAMFILES%\Example\example.exe
│   ├─ REGISTRY SET
│   │   └─ HKLM\...\Uninstall\Example::DisplayName
│   │       from: (yok)
│   │       to:   Example 2.1
│   └─ SERVICE CREATE
│       └─ ExampleService
│
└─ example.exe
    ├─ FILE CREATE
    │   └─ %APPDATA%\Example\config.json
    ├─ DNS
    │   └─ api.example.com
    └─ HTTP(S)
        └─ POST https://api.example.com/v3/register
            ├─ İstek meta verisi
            ├─ Yanıt meta verisi
            └─ 1.7 KB gönderildi / 4.2 KB alındı
```

Ardından bu kaydı **taşınabilir bir kaldırma paketine** dönüştürür. Bu paketi CaYaTrace'in
hiç çalışmadığı bir cihaza götürüp orada temizlik yapabilirsiniz — her madde, herhangi bir
şeye dokunulmadan önce o cihazda yeniden doğrulanır.

## Neden böyle tasarlandı

- **Daha çok olay yerine doğru ilişkilendirme.** PID'ler geri dönüştürülür; dosya ve kayıt
  defteri olayları isim değil işaretçi taşır. Bunları yanlış yapmak, kendinden emin ama
  *yanlış* bir ağaç üretir. Bkz. [ilişkilendirme katmanı](docs/ARCHITECTURE.md#3-the-correlation-layer-is-the-product).
- **Neyi kaçırdığı konusunda dürüst.** ETW yük altında olayları sessizce düşürür; bu da
  oturumu gerçekte olduğundan *daha temiz* gösterir. Her oturum kendi veri kalitesini
  raporlar.
- **Çekirdek sürücüsü yok.** Kurulum yok, yeniden başlatma yok, test imzalama modu yok,
  geride bir şey kalmıyor.
  [Nedeni ve bedeli.](docs/ARCHITECTURE.md#1-the-constraint-that-shapes-everything-no-kernel-driver)
- **Cihazı bozamayacak bir kaldırma.** Geçersiz kılınamayan yasak listesi, parmak izi
  doğrulaması, silme yerine karantina, geri alma günlüğü ve varsayılan olarak prova modu.

## Durum — 0.1.0 önizleme

Bu erken bir sürüm. Bugün gerçekten çalışan ile yalnızca tasarlanmış olan dürüstçe ayrılmıştır:

| Alan | Durum |
|---|---|
| Süreç / iş parçacığı / modül izleme, nedensel ağaç | ✅ çalışıyor |
| İsim çözümlemeli dosya ve kayıt defteri izleme | ✅ çalışıyor |
| Kayıt defteri önce → sonra değer geçişleri | ✅ çalışıyor |
| Öncesi/sonrası sistem envanteri ve farkı | ✅ çalışıyor |
| Sürece ilişkilendirilmiş ağ akışları (çekirdek) | ✅ çalışıyor |
| DNS sorguları ve yanıtları, isteyen sürece ilişkilendirilmiş | ✅ çalışıyor |
| TLS el sıkışma meta verisi (Schannel) | ✅ çalışıyor |
| WinINet / WinHTTP uygulamalarından tam URL'ler | ✅ çalışıyor |
| Oturum depolama, JSONL günlüğü, veri kalitesi raporu | ✅ çalışıyor |
| Kaldırma planlayıcı, `.ctpkg` paketleri, kaldırma motoru | ✅ çalışıyor |
| Komut satırı (`trace`, `report`, `remediate`) | ✅ çalışıyor |
| Çalışma tezgâhı arayüzü (WebView2 + CaYaDev teması) | 🚧 devam ediyor |
| Süreçlere ilişkilendirilmiş Pktmon paket yakalama | ✅ çalışıyor |
| Tam istek gövdeleri için araya giren proxy (isteğe bağlı) | 📐 tasarlandı |
| Çoklu VM karşılaştırması (`compare`) ve ölçülmüş yol şablonlama | ✅ çalışıyor |
| Gerekçeleri görünür risk puanlama | ✅ çalışıyor |
| Model yeterlilik testli Ollama entegrasyonu | ✅ çalışıyor |
| VirusTotal itibar sorgusu (hash ile, asla yükleme yapmaz) | ✅ çalışıyor |
| Kategori seçimli HTML / CSV dışa aktarma | 📐 tasarlandı |

## Hızlı başlangıç

`CaYaTrace.exe` dosyasını [Releases](https://github.com/CaYatur/CaYaTrace/releases)
bölümünden indirin. Taşınabilirdir — kurulum yok, servis yok, kendi klasörü dışına hiçbir
şey yazmaz.

```bash
CaYaTrace trace --target "C:\Downloads\setup.exe" --duration 120
```

Bulduklarını görüntüleyin:

```bash
CaYaTrace report --session .\sessions
```

Kayıttan bir kaldırma paketi oluşturun:

```bash
CaYaTrace report --session .\sessions --export-package Example.ctpkg
```

Kaldırmayı herhangi bir cihazda önizleyin (`--apply` olmadan hiçbir şey değişmez):

```bash
CaYaTrace remediate --package Example.ctpkg
```

Aynı programı iki VM'de kaydedip karşılaştırın — her ikisinde de tekrar edenler programın
gerçek davranışı, farklı olan yollar ise paketin taşıdığı *ölçülmüş* şablonlar olur:

```bash
CaYaTrace compare .m-a .m-b --export-package Example.ctpkg
```

Arayüz için `CaYaTrace` komutunu argümansız çalıştırın; tüm seçenekler için
`CaYaTrace help` kullanın.

> **Çekirdek izleme yönetici yetkisi ister.** Yetki olmadan da CaYaTrace öncesi/sonrası
> sistem envanterlerini kaydeder ve neyi atladığını açıkça söyler — programın hiçbir şey
> yapmadığı izlenimi vermez.

## Gereksinimler

- Windows 10 (1809+) veya Windows 11, x64 ya da ARM64
- Çekirdek izleme için yönetici yetkisi — geri kalan her şey yetkisiz çalışır
- Çalışma tezgâhı arayüzü için
  [WebView2 çalışma zamanı](https://developer.microsoft.com/microsoft-edge/webview2/)
  (Windows 11'de hazır gelir; komut satırı buna ihtiyaç duymaz)

## Kaynaktan derleme

[.NET 8 SDK](https://dotnet.microsoft.com/download) gerekir.

```bash
git clone https://github.com/CaYatur/CaYaTrace.git
cd CaYaTrace
dotnet test
dotnet publish src/CaYaTrace.App -c Release -r win-x64 -o dist
```

Kırpma (trimming) bilinçli olarak kapalıdır —
[nedeni burada](docs/ARCHITECTURE.md#9-packaging).

## Dil

Arayüz Windows görüntü dilini izler: Türkçe sistemde Türkçe, diğer her yerde İngilizce.
Geçersiz kılmak için `CAYATRACE_LANGUAGE=tr` veya `=en` ayarlayın.

Ağaçtaki işlem adları (`FILE CREATE`, `REGISTRY SET`) her dilde İngilizce kalır; böylece
raporlar diller arasında karşılaştırılabilir ve aranabilir olur.

## Belgeler

| | |
|---|---|
| [Mimari](docs/ARCHITECTURE.md) | Motorun nasıl çalıştığı ve sınırları |
| [Paket biçimi](docs/PACKAGE-FORMAT.md) | `.ctpkg` kaldırma paketi |
| [Yol haritası](docs/ROADMAP.md) | Neyin, hangi sırayla planlandığı |
| [Güvenlik](SECURITY.md) | Kanıt verisinin ele alınması; güvenlik açığı bildirimi |
| [Katkı](CONTRIBUTING.md) | |

## İlgili proje

[CaYa Network Forensic Observer](https://github.com/CaYatur/CaYa-Network-Forensic-Observer) —
yalnızca ağ odaklı öncülü. CaYaTrace, sistem değişikliği izleme, nedensel ilişkilendirme ve
kaldırma yetenekleri ekleyerek onun yerini alır.

## Lisans

MIT © 2026 [CaYatur](https://github.com/CaYatur) · [CaYaDev](https://cayadev.com)

# Play Store Submission Checklist

Bu dosya, `UstaBul` Android uygulamasini Google Play'e yuklemeden once son kontrol listesi olarak kullanilir.

## Hazir teknik bilgiler

- Uygulama adi: `UstaBul`
- Android application id: `com.ustabul.mobile.ustabul_mobile`
- Version name: `1.0.0`
- Version code: `1`
- Hedef backend: `https://ustabul.onrender.com`
- Privacy policy URL: `https://ustabul.onrender.com/gizlilik-politikasi/`
- Account deletion URL: `https://ustabul.onrender.com/hesap-silme/`
- Destek e-postasi: `ustabulcyprus@gmail.com`

## Hazir artefaktlar

- Release AAB:
  `mobile_app/build/app/outputs/bundle/release/app-release.aab`
- SHA256:
  `8AE2EC99F69F07F805A731F322D601B45E73732632619F35A425FD2ED80E1DD2`

## Signing dosyalari

Asagidaki dosyalar olusturuldu ve git'e eklenmez:

- `mobile_app/android/key.properties`
- `mobile_app/android/keystore/release-keystore.jks`

Bu iki dosyayi mutlaka guvenli bir yerde yedekleyin. Gelecekte ayni uygulamayi guncellemek icin ayni upload anahtari gerekecek.

Yeniden olusturma yardimci script'i:

- `scripts/generate_android_release_keystore.ps1`

## Play Console'a girmeden once

- `Privacy Policy` alanina su URL'yi yaz:
  `https://ustabul.onrender.com/gizlilik-politikasi/`
- `Account deletion` / `Data deletion` alanina su URL'yi yaz:
  `https://ustabul.onrender.com/hesap-silme/`
- Support email alanina su adresi yaz:
  `ustabulcyprus@gmail.com`

## Play Console icinde manuel doldurulacaklar

- App access:
  Giris gerekiyorsa review icin demo hesap ver.
- Data safety:
  Toplanan veriler, iletisim bilgileri, hesap bilgileri, mesajlar, talep/randevu verileri ve cihaz bildirimi token akisini dogru beyan et.
- Data deletion:
  Uygulama ici silme yolu ve web silme linkini beyan et.
- Store listing:
  Kisa aciklama, uzun aciklama, ikon, feature graphic, telefon ekran goruntuleri.
- Content rating:
  Anketi doldur.
- Ads:
  Uygulamada reklam yoksa `No ads` sec.

## Yuklemeden once son kontrol

- `flutter analyze`
- `python manage.py check`
- Gercek cihazda login
- Talep olusturma
- Usta paneli / Islerim
- Mesajlar
- Bildirimler
- Gizlilik politikasi sayfasi
- Hesap silme ekrani

## Kalan dis bagimliliklar

- Push aktif olacaksa `mobile_app/android/app/google-services.json` eklenmeli.
- Play Console formlari repo icinden doldurulamaz; manuel tamamlanmali.
- Magaza ekran goruntuleri ve aciklamalar manuel hazirlanmali.

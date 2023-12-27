# Analiza ranjivosti, napada i mitigacija za Java Spring Boot i Neo4j tehnologije

U narednim poglavljima biće prikazan deo sistema koji će biti analiziran, data stabla napada, kao i biti priložen propratni tekst za ta stabla.

U nastavku je naveden dijagram koji ističe deo sistema koji se analizira, koji uključuje serversku aplikaciju izgrađenu u Java Spring Boot tehnologiji i Neo4j graf bazu podataka.

![Dijagram](/Dijagrami/SpringBootNeo4j.jpg)

## Java Spring Boot

Java Spring Boot je jedna od najpopularnijih tehnologija koje se danas koriste za implementaciju backend sistema. Ono što ovu tehnologiju čini zanimljivom za analizu jeste njena modularnost, odnosno korišćenje Node Package Manager-a (NPM) za ubacivanje zavisnosti i paketa koji su drugi developeri implementirali. Dovoljno je da se u nekom od "čvorova" u lancu zavisnosti pronađe neka ranjivost, da bi se ta ranjivost kasnije eksploatisala u kranjem proizvodu. U nastavku sledi detaljan opis dve vrste ranjivosti i jedne vrste napada koji se mogu naći u softverima koji koriste ovu tehnologiju: XXE Vulnerability [[1]](#reference), SSRF (Server-Side Request Forgery) [[2]](#reference), i DoS [[3]](#reference).

#### Stablo napada

![Dijagram](/Dijagrami/AttacksTree.jpg)

### SSRF (Server-Side Request Forgery)

Prevare sa zahtjevima s serverske strane su ranjivost koja omogućava napadaču da izazove aplikaciju na serverskoj strani da šalje zahtjeve prema neželjenoj lokaciji.

U tipičnom napadu SSRF-a, napadač može naterati server da se poveže s internim servisima samo unutar infrastrukture organizacije. U drugim slučajevima, moguće je prisiliti server da se poveže s proizvoljnim vanjskim sistemima. Ovo može rezultirati curenjem osjetljivih podataka, poput autorizacijskih podataka.

Uspješan SSRF napad često može rezultirati neovlaštenim radnjama ili pristupom podacima unutar organizacije. To može biti u vezi s ranjivom aplikacijom ili drugim serverskim sistemima s kojima aplikacija može komunicirati. U nekim situacijama, ranjivost SSRF-a može omogućiti napadaču izvođenje proizvoljnog izvršavanja naredbi.

SSRF eksploatacija koja uzrokuje povezivanje s vanjskim sistemima trećih strana može rezultirati zlonamjernim napadima koji izgledaju kao da potiču od organizacije koja hostuje ranjivu aplikaciju.

SSRF napadi često iskorištavaju povjerenje kako bi eskalirali napad iz ranjive aplikacije i izvršavali neovlaštene radnje. Odnosi povjerenja mogu postojati u vezi sa serverom ili s drugim sistemom unutar iste organizacije.

U SSRF napadu protiv servera, napadač uzrokuje da aplikacija šalje HTTP zahtev natrag ka serveru koji hostuje aplikaciju, putem njegovog mrežnog interfejsa petlje. Ovo obično uključuje dostavljanje URL-a sa imenom domaćina poput 127.0.0.1 (rezervisana IP adresa koja pokazuje na interfejs petlje) ili localhost (često korišćen naziv za isti adapter).

Primer: Zamislimo aplikaciju za kupovinu koja omogućava korisnicima da pregledaju dostupnost određenog proizvoda u određenoj prodavnici. Da bi pružila informacije o stanju zaliha, aplikacija mora upitati različite REST API-je slanjem URL-a relevantnom backend API endpointu putem HTTP zahteva sa prednje strane. Kada korisnik pregleda status zaliha za proizvod, njihov preglednik šalje sledeći zahtev:

<per>
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118
stockApi=http://stock.weliketoshop.net:8080/product/stock/check%3FproductId%3D6%26storeId%3D1
</pre>

Ovo uzrokuje da server šalje zahtev prema navedenom URL-u, dohvata status zaliha i vraća ga korisniku.

U ovom primeru, napadač može modifikovati zahtev kako bi naveo URL lokalnom serveru:

<pre>
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://localhost/admin
</pre>

Server dohvata sadržaj URL-a /admin i vraća ga korisniku.

Napadač može posetiti URL /admin, ali administratorska funkcionalnost obično je dostupna samo ovlašćenim korisnicima. To znači da napadač neće videti ništa od interesa. Međutim, ako zahtev za URL-om /admin dolazi sa lokalne mašine, normalne kontrole pristupa se zaobilaze. Aplikacija dodeljuje potpuni pristup administratorskoj funkcionalnosti jer zahtev izgleda kao da potiče sa pouzdane lokacije.

Osnovni SSRF protiv lokalnog servera
Zašto aplikacije reaguju na ovaj način i implicitno veruju zahtevima koji dolaze sa lokalne mašine? To može proizaći iz različitih razloga:

Provera kontrole pristupa može biti implementirana u drugom komponentu koji se nalazi ispred aplikativnog servera. Kada se uspostavi veza prema serveru, provera se zaobilazi.
Iz razloga oporavka od katastrofe, aplikacija može dozvoliti administrativni pristup bez prijave bilo kom korisniku koji dolazi sa lokalne mašine. To pruža način administratoru da povrati sistem ako izgubi svoje akreditacije. Ovo pretpostavlja da bi samo potpuno pouzdani korisnik došao direktno sa servera.
Administrativno sučelje može slušati na drugom broju porta u odnosu na glavnu aplikaciju i možda nije dostupno direktno korisnicima.
Ovakvi odnosi poverenja, gde zahtevi koji dolaze sa lokalne mašine se obrađuju drugačije od običnih zahteva, često čine SSRF kritičnom ranjivošću.

#### Mitigacije

Mitigacije za DoS (Denial of Service) napade uključuju niz pristupa i tehnika koje se mogu primeniti kako bi se smanjili efekti ovakvih napada.U nastaku slede neke od njih.

##### Bela Lista i DNS rezolucija

Najsigurniji način da se izbegne napad server-side request forgery (SSRF) je upotreba bele liste imena hosta (DNS imena) ili IP adresa kojima vaša aplikacija treba pristupiti. Ako pristup beloj listi nije pogodan za vašu situaciju i morate se osloniti na crnu listu, važno je pravilno validirati korisnički unos. Na primer, ne dozvoljavajte zahteve ka krajnjim tačkama sa privatnim (nerutabilnim) IP adresama (detaljno navedeno u RFC 1918).

Međutim, u slučaju crne liste, pravilna mera zaštite će se razlikovati od aplikacije do aplikacije. Drugim rečima, nema univerzalnog rešenja za SSRF jer to zavisi od funkcionalnosti aplikacije i poslovnih zahteva.

##### Obrada odgovora

Da biste sprečili curenje podataka odgovora napadaču, moramo se uveriti da primljeni odgovor odgovara očekivanom formatu. Pod nikakvim okolnostima, sirovi odgovor od poslatog zahteva ne bi trebalo dostavljati klijentu.

##### Onemogućavanje nepotrebnih URL šema

Ako aplikacija koristi samo HTTP ili HTTPS za slanje zahteva, dozvolimo samo ove URL šeme. Ako onemogućimo nepotrebne URL šeme, napadač neće moći koristiti veb aplikaciju za slanje zahteva koristeći potencijalno opasne šeme poput file:///, dict:///, ftp:// i gopher://.

##### Autentifikacija na internim servisima

Podrazumevano, servisi poput Memcached-a, Redis-a, Elasticsearch-a i MongoDB-a ne zahtevaju autentifikaciju. Napadač može koristiti ranjivosti server-side request forgery da pristupi nekim od ovih servisa bez ikakve autentifikacije. Stoga, radi zaštite osetljivih informacija i osiguranja bezbednosti veb aplikacije, preporučuje se omogućavanje autentifikacije gde god je to moguće, čak i za servise u lokalnoj mreži."

### Denial of Service (DoS) Napadi

Napad uskraćivanja usluge (DoS) je napad koji ima za cilj onesposobiti mašinu ili mrežu, čineći je nedostupnom svojim namenjenim korisnicima. DoS napadi postižu ovo preplavljivanjem cilja saobraćajem ili slanjem informacija koje izazivaju pad sistema. U oba slučaja, DoS napad oduzima legitimnim korisnicima (npr. zaposlenima, članovima ili korisnicima naloga) pristup usluzi ili resursu koji su očekivali.

Žrtve DoS napada često su veb serveri visokoprofilnih organizacija poput banaka, kompanija za trgovinu, medijskih kompanija ili vladinih i trgovinskih organizacija. Iako DoS napadi obično ne rezultiraju krađom ili gubitkom značajnih informacija ili drugih vrednosti, žrtvi mogu prouzrokovati značajne troškove u vremenu i novcu kako bi se sa njima suočili.

Postoje dva opšta metoda DoS napada: poplava usluga ili rušenje usluga. Napadi poplave dešavaju se kada sistem prima previše saobraćaja, zbog čega serveri usporavaju i na kraju se zaustavljaju.

Popularni napadi poplave uključuju:

1. Napadi prelivanja bafera - najčešći DoS napad. Koncept je slanje više saobraćaja ka mrežnoj adresi nego što su programeri izgradili sistem da može da podnese. Ovo uključuje napade navedene ispod, kao i druge dizajnirane da iskoriste bagove specifične za određene aplikacije ili mreže.

2. ICMP poplava - koristi netačno konfigurisane mrežne uređaje slanjem falsifikovanih paketa koji pingaju svaki računar na ciljanoj mreži, umesto samo jednog određenog računara. Mreža zatim pojačava saobraćaj. Ovaj napad takođe poznat kao smurf napad ili ping smrti.

3. SYN poplava - šalje zahtev za povezivanje sa serverom, ali nikada ne završava rukovanje. Nastavlja se dok svi otvoreni portovi ne budu zasićeni zahtevima i nijedan nije dostupan za povezivanje legitimnim korisnicima.

Drugi DoS napadi jednostavno iskorišćavaju ranjivosti koje uzrokuju pad ciljanog sistema ili usluge. U ovim napadima, šalje se unos koji koristi greške u cilju koje zatim dovode do pada ili ozbiljnog destabilizovanja sistema, tako da mu se ne može pristupiti ili ga koristiti.

Primer: Ova DTD ugrađuje entitete unutar entiteta, uzrokujući rekurentno dereferenciranje XML parsera kako bi se došlo do vrednosti korenskog entiteta "lol".

<pre><?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE example [
<!ELEMENT example ANY >
<!ENTITY lol "lol">
<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<example>&lol9;</example>
</pre>

Svaki entitet "lol9" biće proširen u deset "lol8", i svaki od njih će postati deset "lol7", i tako dalje. Na kraju, jedan "lol9" će se proširiti u jednu milijardu "lol"-ova. Ovo može preopteretiti memoriju XML parsera, potencijalno izazivajući njegov pad.

#### Mitigacije

Mitigacije za DoS (Denial of Service) napade uključuju niz pristupa i tehnika koje se mogu primeniti kako bi se smanjili efekti ovakvih napada.U nastaku slede neke od njih.

##### Rate Limiting

Postavljanje ograničenja brzine (rate limiting) na određene vrste zahteva može pomoći u sprečavanju preopterećenja sistema. Ograničavanje broja zahteva koje jedan korisnik ili IP adresa može poslati u određenom vremenskom periodu može značajno smanjiti rizik od DoS napada.

##### Upotreba CDN-a (Content Delivery Network)

CDN može pomoći u distribuciji opterećenja između više servera smeštenih na različitim lokacijama. Ovo može smanjiti pritisak na centralne servere tokom DoS napada.

##### Optimizacija Performansi

Poboljšanje performansi sistema, kao što su optimizacija koda, keširanje, i druge optimizacije, može pomoći da se smanji uticaj DoS napada.

##### Implementacija Brana i Filtriranje Saobraćaja

Korišćenje firewall-a, IDS (Intrusion Detection System) i IPS (Intrusion Prevention System) može pomoći u filtriranju neželjenog saobraćaja pre nego što stigne do serverskih resursa.

## Neo4j

Neo4j je open-source grafovski sistem za upravljanje bazama podataka napisan u Javi. Umesto dokument-orientisanog modela podataka, Neo4j koristi grafovski model, gde su podaci organizovani u čvorovima i odnosima između čvorova. Grafovski model je posebno pogodan za rad s povezanim podacima i analize odnosa između entiteta.

Neo4j nudi sopstveni upitni jezik nazvan Cypher, koji je dizajniran za izražavanje upita i manipulaciju podacima u grafovskom modelu. Cypher omogućava fleksibilne upite koji se lako prilagođavaju specifičnim potrebama korisnika.

Razmatranje ranjivosti u kontekstu Neo4j može uključivati:
Cypher Injection[[4]](#reference),Partial Path Traversal[[5]](#reference).

### Cypher Injection

Cypher injection je vrsta ranjivosti koja se javlja kada se nevalidirani ili nesigurni podaci ubace direktno u Cypher upite u Neo4j bazi podataka. Neo4j koristi Cypher upitni jezik za manipulaciju i pretraživanje podataka u obliku grafa. Cypher injection je ekvivalent SQL injection napada, ali se odnosi na graf baze podataka.

Princip Cypher injection-a je sličan principu SQL injection-a, gde napadač pokušava iskoristiti nedostatak adekvatne kontrole unosa podataka kako bi ubacio zlonamerni Cypher kod u upit. Kada se ova vrsta napada uspešno izvede, napadač može dobiti neovlašćen pristup podacima, vršiti izmene u grafu ili izvršavati druge zlonamerne radnje.

#### Opis napada

U ovoj sekciji biće prikazana 4 tipa Cypher injection-a: Cypher Injection Deletion Attack, Information disclosure, Blind Injection i Error Based Cypher Injection.

##### Cypher Injection Deletion Attack

Kada se u Cypher injection napadu vrše akcije koje rezultiraju brisanjem elemenata iz grafa baze podataka, to se obično opisuje kao "Cypher Injection Deletion Attack". Ova vrsta napada ima za cilj neovlašćeno brisanje podataka iz graf baze podataka Neo4j putem manipulacije Cypher upitima.

<pre>
query = "MATCH (user) WHERE user.id =" + userid + ";"
</pre>

Upit koji je naveden je Cypher upit koji ima za cilj dohvatiti čvor u grafu baze podataka Neo4j čiji je id jednak vrednosti promenljive "userid".

U ovom primeru, kod koji je ubačen je:

<pre>"1 OR 1 = 1 WITH true AS ignored MATCH (all) DETACH DELETE all; //"</pre>

Ako se ovaj zlonamerni kod ubaci umesto userid u originalni upit, rezultat će biti brisanje svih čvorova u grafu, što može imati ozbiljne i nepovratne posledice

##### Information disclosure

Još jedan mogući vektor injekcije javlja se kada napadač koristi zlonamerni unos kako bi pročitao informacije do kojih ne bi trebao imati pristup.

Na primer, ubačen kod:

<pre>
Robby' OR 1=1 RETURN apoc.text.join(collect(s.name), ','); //
</pre>

Može se izvršiti kao:

<pre>

MATCH (s:Student) WHERE s.name = 'Robby' OR 1=1 RETURN apoc.text.join(collect(s.name), ','); //' RETURN s.name;
</pre>

Ovaj upit bi rezultirao dohvatanjem imena svih studenata iz baze podataka i vraćanjem tih imena u jednom nizu razdvojenom zarezima. Da bi ovakav metod uspeo, klijentska aplikacija mora biti podložna injekciji, a takođe mora i vraćati rezultate upita korisniku.

Ovde je ključno razumeti da je cilj ovog napada dobiti neovlašćeni pristup informacijama koje bi inače trebalo zaštititi. Ovaj primer ilustruje kako napadač može iskoristiti ranjivosti u načinu rada aplikacije i baze podataka kako bi došao do podataka koji mu nisu namenjeni.

##### Blind Injection

Kada napadač ne pokušava direktno dohvatiti otkrivene informacije iz odgovora klijenta, već ih može dobiti na drugi način. Jedan način da se to postigne je reagovanjem na ponašanje aplikacije.

Pretpostavimo da veb sajt učitava različite stranice na osnovu rezultata upita. Na primer, stranica za prijavu prvo traži e-poštu i zatim prikazuje ili stranicu za prijavu ili stranicu za registraciju u zavisnosti od rezultata upita.

<pre>
query = "MATCH (user) WHERE user.email = '" + email + "' RETURN user IS NOT NULL;";
</pre>

Rezultat ovog upita se ne vraća korisniku; umesto toga, aplikacija koristi postojanje korisnika kako bi prikazala sledeću stranicu. Na ovaj način, mogući injection može iskoristiti ovo pokretanjem različitih odgovora uslovljeno.

Na primer, Mali Robi želi da vidi kojim korisničkim imenom je njegov brat registrovan:

<pre>
"bobby@mail.com' RETURN user.username STARTS WITH 'a';//
</pre>

Ako korisničko ime počinje sa 'a', upit se razrešava kao tačan i prikazuje se stranica za prijavu. Na ovaj način, Robi može, karakter po karakter, saznati korisničko ime svog starijeg brata sistematskim proveravanjem odgovora za svaki karakter.

##### Error Based Cypher Injection

Još jedan način dobijanja pristupa informacijama je ako zlonamerni akter iskorištava poruke o greškama koje vraća klijentska aplikacija. Ovo se može postići ubacivanjem neispravnih ulaznih podataka koji će izazvati različite poruke o greškama, a na osnovu tih poruka može se dobiti osetljive informacije o bazi podataka. Ove informacije mogu se koristiti za kreiranje napada sa sledećim payload-om.

Ovo može biti jednostavno kao dodavanje dodatnog znaka navoda kako bi se videlo da li će server vratiti celu bazu grešaka. Evo primera jednostavnog unosa:

<pre>Input: ' RETURN a//</pre>

<pre>
MATCH (s:Student) WHERE s.name = '' RETURN a//' RETURN s;
</pre>

Ovo dovodi do sledeće greške baze podataka:

<pre>
Variable `a` not defined (line 1, column 44 (offset: 43))
"MATCH (s:Student) WHERE s.name = '' RETURN a//' RETURN s;"
</pre>

Ako server vraća sirovu grešku, ceo upit je sada vidljiv, čineći lakšim slanje preciznijih zlonamernih inputa nazad. Napadač sada zna imena barem jedne labele kao i povezane promenljive.

#### Mitigacije

U ovoj sekciji biće obrađeni načini da se otklone Cypher ranjivosti, a to su: parametri i APOC procedure, validacija unosa, adekvatna dodela dozvola korisnicima, kao i parametrizacija.

##### Parametri i APOC procedure

Rešenje u ovom slučaju je da i dalje prosleđujete studentName kao parametar APOC proceduri.

<pre>
CALL apoc.cypher.doIt("CREATE (s:Student) SET s.name = $name RETURN true", { name: $studentName })
YIELD value
RETURN value;
</pre>

Ovaj upit koristi APOC proceduru apoc.cypher.doIt kako bi izvršio Cypher upit koji kreira novog studenta sa imenom $studentName. Naredba SET postavlja vrednost atributa "name" novog čvora na vrednost parametra "$name".

Praktično, koristi se prednost parametrizovanih upita kako bi se osigurala bezbednost od injekcija. Parametri se prosleđuju kao deo mape "{ name: $studentName }", gde je "$studentName" vrednost koja se bezbedno ubacuje u upit. Ovo sprečava nepoželjne efekte Cypher injection napada.

##### Validacija unosa

Svrha validacije unosa jeste da se ograniči korisnički unos i spreči izvršavanje neželjenih upita. Na primer, ako očekujemo numerički unos, proverimo da li je unesena vrednost numeričkog tipa pre nego što se koristi u upitu.

##### Adekvatna dodela dozvola

Adekvatno implementirana autorizacija je jedna od najbitnijih koraka koji moraju biti ispunjeni da bi se napravio bezbedan sistem. Samo autorizovan korisnik sme da ima pristup bazi podataka. Svaki korisnik treba da poseduje adekvatne dozvole koje zavise od njegove uloge u sistemu. Na primer, u sistemu koji upravlja podacima o prisustvu studenata, student može proveriti informacije o svom prisustvu, ali ne sme da ih menja. S druge strane, profesor može ažurirati prisustvo studenta.

##### Parametrizovani iskazi

Korisnički unos ne sme biti direktno ubačen u condition statement, i mora biti validiran i isfiltriran. U parametrizaciji, parametrizovani statement-i se koriste za prosleđivanje ulaznih promenljivih. Umesto ugrađivanja korisničkih unosa u condition statement, koriste se parametri. Ovaj mehanizam pomaže kod uklanjanja ranjivosti tako što razdvaja strukturu upita od samih podataka. Vezivanje korisničkog unosa je odvojeno od izvršavanja upita. Parametrizovani upiti automatski vrše "čišćenje" unosa. Pod tim se misli na adekvatno enkodovanje, escaping, kao i validaciju. Ovim se sprečava situacija u kojoj baza interpretira unos kao komandu. Čak i u slučaju da napadač pokuša da ubaci maliciozni kod u polje za unos, ubačen kod je tretiran kao tekst, a ne kao komanda koja se može izvršiti. Sledi kod koji proverava da li upit sadrži neki broj, i vraća grešku ako to nije slučaj.

<pre>
Map<String,Object> params = new HashMap<>();
params.put( "studentName", studentName );

String query =
"CREATE (s:Student)" + "\n" +
"SET s.name = $studentName";

Result result = transaction.execute( query, params );
</pre>

#### Stablo napada

![Dijagram](/Dijagrami/CyberInjectionDiagram.jpg)

### Partial Path Traversal

Ovo je bezbednosna ranjivost koja se odnosi na Directory Traversal (proboj direktorijuma) putem funkcije apoc.log.stream u org.neo4j.procedure:apoc paketu. Ova ranjivost omogućava napadaču da izvede Directory Traversal napad, što znači pristupanje datotekama i direktorijumima izvan očekivanog opsega. Uticaj je ograničen na susedne direktorijume, na primer, "userControlled.getCanonicalPath().startsWith("/usr/out")" omogućava napadaču pristup direktorijumu sa imenom kao što je "/usr/outnot".

Radnje: Ako nije moguće izvršiti nadogradnju biblioteke, preporučuje se kontrolisanje liste dozvoljenih funkcija koje mogu biti korišćene u sistemu.

#### Opis napada

Directory Traversal napad (poznat i kao path traversal) ima za cilj pristupanje datotekama i direktorijumima van predviđenog foldera.
Manipulacijom sa sekvencama "tačka-tačka-kosa crta (../)" ili korišćenjem apsolutnih putanja, napadač može pristupiti proizvoljnim datotekama i direktorijumima na sistemskom nivou, uključujući izvorni kod aplikacije, konfiguraciju i druge kritične sistemsko-fajlove.pogođene verzije: [4.3.0.7) i [4.4.0.0, 4.4.0.8).

Tipovi Directory Traversal Ranjivosti:

##### Information Disclosure

Otkrivanje Informacija (Information Disclosure): Ovo omogućava napadaču da dobije informacije o strukturi foldera ili čita sadržaj osetljivih datoteka na sistemu.
Modul st za serviranje statičkih datoteka na veb stranicama sadrži ovu vrstu ranjivosti. U našem primeru, služićemo datoteke sa javne rute.

Ukoliko napadač zatraži sledeći URL sa našeg servera, to će rezultirati curenjem osetljivog privatnog ključa root korisnika:

<pre>
curl http://localhost:8080/public/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/root/.ssh/id_rsa
</pre>

Napomena: "%2e" je URL enkodirana verzija tačke (.).

Ovaj zahtev putem curl komande koristi manipulaciju putanjom (../) kako bi pokušao pristupiti osetljivim datotekama izvan predviđenog direktorijuma. Konkretno, u ovom slučaju, napadač pokušava dobiti pristup privatnom ključu root korisnika smeštenom u /root/.ssh/id_rsa.

##### Writing arbitrary files

Pisanje proizvoljnih datoteka (Writing arbitrary files): Ovo omogućava napadaču da kreira ili zameni postojeće datoteke. Ova vrsta ranjivosti takođe je poznata kao "Zip-Slip".

Jedan način postizanja ove ranjivosti je korišćenjem zlonamernog zip arhiva koji sadrži putanje koje prodiru kroz direktorijume. Kada se svako ime datoteke u zip arhivu konkatenira sa ciljnim direktorijumom bez validacije, rezultirajuća putanja može završiti izvan ciljanog foldera. Ako se izvršna ili konfiguraciona datoteka prepiše datotekom koja sadrži zlonamerni kod, problem se može lako pretvoriti u pitanje izvršavanja proizvoljnog koda.

Primer zlonamernog zip arhiva:

<pre>
2018-04-15 22:04:29 ..... 19 19 dobro.txt
2018-04-15 22:04:42 ..... 20 20 ../../../../../../root/.ssh/authorized_keys
</pre>

U ovom primeru, arhiv ima jednu bezopasnu datoteku (dobro.txt) i jednu zlonamernu datoteku (../../../../../../root/.ssh/authorized_keys). Ekstrakcija zlonamerne datoteke dovodi do proboja izvan ciljanog foldera, završava u /root/.ssh/ i prepiše datoteku authorized_keys.

Ova ranjivost predstavlja ozbiljan sigurnosni rizik jer omogućava napadaču da manipuliše sistemskim datotekama i izvršava proizvoljni kod, čime može ozbiljno ugroziti bezbednost sistema.

#### Mitigacije

Ako se ne može izvršiti nadogradnja biblioteke, jedna od mogućih mitigacija jeste kontrolisanje dozvoljenih funkcija koje se mogu koristiti u sistemu. To se obično postiže kontrolom "dozvoljene liste" (allowlist) funkcija koje su dozvoljene ili zabranjene za upotrebu.

Evo nekoliko koraka koji se mogu preduzeti kako bi se ograničili rizici povezani sa spomenutom ranjivošću:

##### Dozvoljena Lista (Allowlist)

Sastavite listu dozvoljenih funkcija i ograničite izvršavanje samo na funkcije navedene na toj listi. Ovo može značiti konkretno određivanje koji se Neo4j Cypher izrazi mogu koristiti.

##### Praćenje i Logovanje

Implementirajte sistem praćenja i logovanja koji beleži sve upite i operacije koje se izvršavaju, kako biste imali pregled o aktivnostima i eventualnim pokušajima zloupotrebe.

##### Kontrola Korisničkih Pristupa

Ograničite privilegije korisnika na minimum neophodan za obavljanje njihovih zadataka. Ako korisnicima nije potrebno da izvršavaju određene operacije, onda im nemojte dozvoliti pristup tim operacijama

##### Ažuriranje

Ažuriranje biblioteke na najnoviju verziju predstavlja najbolju praksu.
Od verzije 5 ispravljena je ova ranjivost. U nastavku sledi prikaz resenja.
Popravljena ranjivost pri prelasku putanje[[6]](#reference).

Sledi kod koji predstavlja izmenu koja se odnosi na proveru staze datoteke u odnosu na određeni direktorijum, s ciljem obezbeđivanja bezbednosti i izbegavanja ranjivosti Directory Traversal.

![Dijagram](/Dijagrami/PathTraversalCommit.jpg)

#### Stablo napada

![Dijagram](/Dijagrami/DirectoryTraversalAttackTree.jpg)

# Reference

[1] https://www.imperva.com/learn/application-security/xxe-xml-external-entity/

[2] https://portswigger.net/web-security/ssrf

[3] https://www.hackerone.com/knowledge-center/xxe-complete-guide-impact-examples-and-prevention

[4] https://neo4j.com/developer/kb/protecting-against-cypher-injection/

[5] https://security.snyk.io/vuln/SNYK-JAVA-ORGNEO4JPROCEDURE-2980272

[6] https://github.com/neo4j-contrib/neo4j-apoc-procedures/pull/3462/files

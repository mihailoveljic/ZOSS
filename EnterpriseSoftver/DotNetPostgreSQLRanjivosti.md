# Analiza ranjivosti, napada i mitigacija za .NET i PostgreSQL tehnologije

## Uvod
U ovom dokumentu biće opisani neki od mogućih napada na deo posmatranog sistema koji koristi .NET, Entity framework, WCF i PostgreSQL tehnologije.

![Dijagram](/Dijagrami/DotNet/DotNet.jpg)

# .NET
.NET platforma je sveobuhvatni ekosistem razvoja softvera koji pruža snažne alate i okruženje za kreiranje raznovrsnih aplikacija  uključujući web, desktop i mobile, koristeći više jezika poput C#, VB.NET i F#. Kada je u pitanju bezbednost, .NET platforma pruža robustne mehanizme zaštite podataka i aplikacija, uključujući integrisane alatke za upravljanje identitetima i pristupom, kao i mehanizme enkripcije podataka. U nastavku će biti opisane ranjivosti pronađene tokom istraživanja ove tehnologije.

## JSON Deserialization Exploit
Problem deserializacija podataka poznat je u mnogim programskim jezicima, pa tako i u .NET platformi. Nebezbedna deserializacijom je  ranjivost čijom eksploatacijom napadač može da umesto očekivanog serializovanog objekta, prosledi maliciozni kod koji će se izvršiti u aplikaciji. 

### Stablo napada

![Dijagram](/Dijagrami/DotNet/JsonDeserialization.jpg)


### Opis napada

U nastavku je opisano kako izgleda napad na aplikaciju koja koristi Json.NET biblioteku, najkorišćeniju biblioteku za serializaciju JSON podataka u .NET-u. 

Postoje 2 preduslova koja moraju biti ispunjena kako bi se napad mogao sprovesti. Prvi je da je **TypeNameHandling** parametar iz **JsonSerializationSettings**-a bilo šta osim podrazumevanog **None**. Ovo podešavanje govori biblioteci da upiše tip serializovanog objekta u "$type"  polje i kasnije pročita to polje prilikom deserializacije. Drugi uslov je da se JSON deserializuje u neki nadtip objekta iz malicioznog JSON-a, ili u generički object tip. U nastavku je primer ranjive konfiguracije [3]:

```
var deserialized = JsonConvert.DeserializeObject<object>(json, new JsonSerializerSettings()
{
     TypeNameHandling = TypeNameHandling.All
});
```

Kada su ova dve preduslova ispunjena, napadač može serializuje bilo koji objekat, čak i one koji nisu očekivani od strane aplikacije. Ovakav objekat se na razne načine može proslediti aplikaciji, npr. kroz REST endpoint, HTTP header, ili bilo kojim drugim načinom razmene podataka koji očekuje JSON.

U nastavku su navedeni neki od primera malicioznih JSON stringova kao i opis šta oni rade u napadnutoj aplikaciji [4].

#### Postavljanje read-only atributa na fajl
```
{
   "$type": "System.IO.FileInfo, System.IO.FileSystem",
   "fileName": "test.txt",
   "isReadOnly": true
}
```

#### Menjanje naziva Windows particije
Ovaj napad zahteva da je aplikacija pokrenuta sa administratorskim privilegijama. Navedeni kod menja naziv d particije u "changed volume".
```
{
   "$type": "System.IO.DriveInfo, System.IO.FileSystem.DriveInfo", 
   "driveName": "d",
   "VolumeLabel": "changed volume"
}
```

#### Izvršavanje komande
Navedeni JSON string će pokrenuti kalkulator na računaru na kome aplikacija radi. Ovaj tip komande će raditi samo na .NET Framework ili .NET Core WPF aplikacijama.
```
{
  "$type": "System.Windows.Data.ObjectDataProvider,    PresentationFramework",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib",
    "$values": [ "cmd", "/c calc.exe" ]
  },
  "ObjectInstance": {
   "$type": "System.Diagnostics.Process, System"
  }
}
```

### Mitigacije

#### Postaviti TypeNameHandling na None 
Korišćenjem podrazumevane **None** vrednosti **TypeNameHandling** podešavanja je jedina vrednost ovog podešavanja koja je imuna na napad. Kada je ovo podešavanje aktivno, napadač ne može da kaže biblioteci koji u tip bi poslati JSON trebalo deserializovati.

#### Koristiti tačan tip koji se deserializuje
Ukoliko se zna da se primljeni JSON deserializuje u neki specifični tip, postaviti taj tip u pozivu metode za deserializaciju. Pravilno konfigurisan kod za deserializaciju izgleda ovako:

```
var deserialized = JsonConvert.DeserializeObject<User>(json, new JsonSerializerSettings()
{
     TypeNameHandling = TypeNameHandling.None
});
```
U ovom primer, User je tip objekta koji se očekuje u primljenom JSON-u., dok **TypeNameHandling.None** naznačava da ne treba čitati "$type" polje prilikom deserializacije. 

#### Validacija primljenih podataka

Ukoliko je potrebno koristiti neku vrednost **TypeNameHandling** polja osim **None**, pristigle podatke trebalo bi validirati korišćenjem **SerializationBinder**-a. U nastavku je primer klase koja implementira logiku za proveru pristiglog tipa. 

```
		class MyBinder : DefaultSerializationBinder
		{
			public override Type BindToType(string assemblyName, string typeName)
			{
				if (typeName == "User")
				{
					return typeof(User);
				}
				throw new InvalidOperationException($"Deserialization of type {typeName} is not allowed.");
			}
		}
```
Ova klasa proverava da li je pristigli objekat tipa User, u suprotnom će baciti exception. Instancu ove klase potrebno je proslediti klasi koja deserializuje pristigle objekte na sledeći način:
```
			var deser = JsonConvert.DeserializeObject(json, new
				JsonSerializerSettings
			{
				TypeNameHandling = TypeNameHandling.All,
				SerializationBinder = new MyBinder()
			});
```


## Entity Framework SQL Injection

### Stablo napada

![SQLInjection](/Dijagrami/DotNet/SQLInjection.jpg)

### Opis napada
SQL injection je prilično poznat napad gde zlonamerni korisnik umesto predviđenog podatka šalje maliciozni SQL kod koji mu omogućava neovlašćen pristup ili brisanje podataka iz baze. Mogućnosti sprovođenja ovog napada prilično su umanjene u modernim jezicima i radnim okvirima, ali i dalje postoje stvari na koje treba obratiti pažnju.

Najpopularniji radni okvir za rad sa bazama podataka u .NET okruženju je Entity Framework. Međutim postoje slučajevi kada je potrebno napisati upit pomoću SQL-a. To mogu biti upiti koji se ne mogu izvršiti pomoću LINQ izraza, upiti koji su previše spori kada se generišu ovim putem ili upiti koji koriste neke komande specifične za odabranu bazu podataka. U tom slučaju potrebno je te upite napisati kao SQL komande. U nastavku jednostavan primer jednog takvog upita.

```
WITH temporaryTable(averageValue) as
    (SELECT avg(Salary)
    from Employee)
        SELECT EmployeeID,Name, Salary 
        FROM Employee, temporaryTable 
        WHERE Employee.Salary > temporaryTable.averageValue
        AND Employee.Company = '';
```
Prethodni izraz pronalazi radnike iz određene kompanije koji imaju platu veću od proseka svih radnika. Ovo je primer izraza koji koristi WITH klauzulu koja ne postoji u LINQ te da bi se iskoristila mora se napisati SQL upit. 

U nastavku se može videti poziv prethodnog upita pomoću Entity framework-a koji je ranjiv na SQL injection zbog konkatenacije stringova.

```
public IEnumerable<Employee> GetEmployesWithAboveAverageSalary(string company)
{
  return context.Database.SqlQueryRaw<Employee>(
    "WITH temporaryTable(averageValue) as
      (SELECT avg(Salary)
      from Employee)
          SELECT EmployeeID,Name, Salary 
          FROM Employee, temporaryTable 
          WHERE Employee.Salary > temporaryTable.averageValue
          AND Employee.Company = {company}");
}
```

S obzirom da koristi Entity framework programer može pomisliti da je potpuno bezbedan od SQL injection napada, međutim izvršavanjem SQL komandi koje nastaju konkatenacijom korisničkog unosa i SQL izraza komanda će direktno biti poslata bazi podataka. Na taj način aplikacija postaje podložna SQL injection napadu.

### Mitigacije
Entity framework, kada se pravilno koristi, u potpunosti sprečava mogućnost SQL injection napada. Međutim postoje neki slučajevi gde treba obratiti posebnu pažnju prilikom generisanja upita nad bazom. U nastavku su navedene neke mitigacije koje pomažu u zaštiti od ovog napada. [1]

#### Korišćenje parametrizovanih upita
    
Kada se za generisanje upita nad bazom koristi Entity framework u kombinaciji sa LINQ izrazimo, upiti će automatski biti parametrizovani. Međutim, kada se se upiti pišu u SQL-u, odnosno nastaju konkatenacijom SQL komandi i parametara, oni neće biti parametrizovani, već to programer mora uraditi. U nastavku je prikazan deo koda koji kreira parametrizovanu SQL komandu [1].
```
public IEnumerable<Employee> GetEmployesWithAboveAverageSalary(string company)
{
  var company = new SqlParameter("company ", "Google");

  return context.Database.SqlQueryRaw<Employee>(
    "WITH temporaryTable(averageValue) as
      (SELECT avg(Salary)
      from Employee)
          SELECT EmployeeID,Name, Salary 
          FROM Employee, temporaryTable 
          WHERE Employee.Salary > temporaryTable.averageValue
          AND Employee.Company = @company", company);
}
```
    
#### Validacija unosa korisnika

Čak i kada je prethodni korak ispoštovan, svi unosi korisnika bi trebalo da budu validirani. Na ovaj način osigurava se da su svi podaci koji ulaze u sistem pravilno formirani i da ne sadrže maliciozni kod. Validaciju unetih podataka trebalo bi sprovesti što ranije, po mogućstvu čim su dobijeni od korisnika.

Validaciju podataka bi trebalo sprovesti nad svim podacima dobijenim od spoljašnjih izvora, a ne samo od korisnika. Na taj način se sistem štiti od potencijalno kompromitovanih komponenti sa kojima sarađuje.

Iako validacija ne bi trebalo da bude primarni način odbrane, ukoliko je pravilno implementirana, ona u velikoj meri može doprineti smanjenju uticaja ovakvih napada na sistem [2].

#### Izbegavanje SQL komandi

SQL komande treba koristiti samo onda kada su neophodne jer mogu uneti ranjivosti u softver ukoliko nisu pravilno implementirane. Koristiti LINQ izraze kada god je to moguće [1].

# Windows Communication Foundation (WCF)

Windows Communication Foundation (WCF) predstavlja moćan i fleksibilan framework razvijen od strane Microsoft-a, namenjen olakšavanju implementacije distribuirane komunikacije u .NET okruženju. Sa svojom sposobnošću da podržava različite protokole, poput HTTP, TCP i MSMQ, WCF omogućava razvoj skalabilnih i interoperabilnih servisno-orijentisanih aplikacija. U nastavku će biti opisane ranjivosti pronađene tokom istraživanja ove tehnologije.

## Hashtable Vulnerability

Ova ranjivost postoji u aplikacijama čiji data contract-i sadrže heš tabele ili liste. Problem nastaje kada se veliki broj vrednosti koje imaju istu heš vrednost dodaju u heš tabelu. Tada može doći do nedostupnosti aplikacije usled prevelikog opterećenja [5]. 

### Stablo napada

![HashTable](/Dijagrami/DotNet/WCFHashTable.jpg)

### Opis napada

Heš tabela predstavlja struktura podataka koja koristi heš funkciju za preslikavanje ključeva u njima pridružene vrednosti. S obzirom da su generisane heš vrednosti fiksne veličine, proizilazi da postoji ograničen broj ovih vrednosti, te može doći do kolizije. Kolizija znači da će jedna heš vrednost pokazivati na više zapisa, odnosno različiti zapisi će imati istu heš vrednost. 

Problem nastaje kada se u heš tabelu unosi velika količina podataka, od kojih značajan broj generiše istu heš vrednost. U slučaju istih heš vrednosti, ti unosi se vezuju u linkovanu listu koja se čuva pod tim ključem odnosno heš vrednošću. Kako lista raste tako i performanse operacija nad heš tabelom opadaju.

Napadač može iskoristiti ovaj propust i sprovesti DoS napad što pošalje veliki broj unosa koji imaju imaju istu heš vrednost i na taj način značajno uspori servis ili izazove njegovu nedostupnost. Količina unosa potrebnih da se izazove nedostupnost servisa zavisi od performansi računara na kome se softver izvršava.

### Mitigacije

#### Podešavanje MaxReceivedMessageSize parametra
Pažljivim podešavanjem limita za veličinu primljenih poruka u dobro meri se može sprečiti uticaj ovakvih napada na servis. Ukoliko poruka veća od limita pristigne, baciće se **QuotaExceededException**. Ako se ovaj izuzetak desi servis se oporavlja tako što odbacuje problematičnu poruku i nastavlja da obrađuje sledeće poruke.

#### Izbegavanje korišćenja heš tabela u data contract-ima
Korišćenjem neke druge strukture prigodne za specifični problem može se potpuno izbeći ovaj napad.

## XML-Based Streaming Attacks - Mixing Streaming and Buffering Transport Modes

WCF framework može da šalje poruke u bafer ili striming transfer modu. U podrazumevanom bafer modu, poruka mora biti kompletno dostavljena kako bi mogla da se čita. U striming modu primalac može da počne da obrađuje poruke pre nego što je ona potpuno dostavljena. To je korisno kada je poruka predugačka i može se serijski obrađivati. Korisno je za i poruke koje su prevelike da bi stale u bafer.

### Stablo napada

![WcfXml](/Dijagrami/DotNet/WCFXML.jpg)

### Opis napada

Pretpostavimo da postoji service contract sa dve operacije, jedna prima Stream, a druga niz objekata. **MaxReceivedMessageSize** je postavljen na veliku vrednost kako bi prva operacija mogla da procesira velike strimove. Međutim, to znači da i druga operacija takođe može da dobije velike poruke, čije podatke deserijalizator baferuje u memoriji kao niz pre nego što se operacija pozove. Ovo je potencijalni DoS napad [5].

Ukoliko napadač zna da je **MaxReceivedMessageSize** postavljen na veliku vrednosti, može konstruisati malicioznu poruku gde je celo telo poruke veliki startni XML tag. Njegov pokušaj čitanja izazvao bi **OutOfMemoryException**. Aplikacija ne može da se oporavi od ovog izuzetka i njegovo pojavljivanje uvek rezultira prekidanjem rada aplikacije. 

### Mitigacije

#### Razdvojiti bafer i striming operacije
Kada god je moguće treba izbegavati korišćenje striming i bafer baziranih operacija u istom service contract-u. Na taj način se limiti mogu posebno postaviti za svaku vrstu operacija. Ukoliko to ipak nije moguće, potrebno je primeniti naredne mitigacije.

#### Ugasiti IExtensibleDataObject funkcionalnost
Ugasiti **IExtensibleDataObject** funkcionalnost postavljanjem  **IgnoreExtensionDataObject** propertija **ServiceBehaviorAttribute** na **true**. Ovo osigurava da će samo članovi koji su deo contract-a biti deserializovani.

#### Postaviti MaxItemsInObjectGraph vrednost
Potrebno je postaviti **MaxItemsInObjectGraph** propertija **DataContractSerializer**-a na bezbednu vrednost. Ovaj limit može se postaviti i kroz **ServiceBehaviorAttribute** atribut. On ograničava broj objekata koji se mogu deserializovati u jednoj epizodi deserializacije.

#### Podesiti sve XML reader limite na bezbedne vrednosti
Bitno je podesiti limite XML readera. Posebnu pažnju treba obratiti na  **MaxDepth**, **MaxStringContentLength** i **MaxArrayLength**.

#### Pregledati known types listu
Pregledati known types listu imajući u vidu da bilo koji od njih može biti instanciran u svakom trenutku.

# Reference

[1] https://shahedbd.medium.com/how-to-mitigating-sql-injection-in-entity-framework-applications-eb058f21758f

[2] https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html

[3] https://blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf

[4] https://systemweakness.com/exploiting-json-serialization-in-net-core-694c111faa15

[5] https://learn.microsoft.com/en-us/dotnet/framework/wcf/feature-details/security-considerations-for-data#avoiding-unintentional-information-disclosure
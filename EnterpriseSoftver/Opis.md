# Enterprise sistem
### Uvod
Posmatrani sistem predstavlja sistem za kupovinu avionskih karata i rezervaciju smeštaja. Sastoji se od nekoliko komponenata: API Gateway, Airline company microservice, Authentification microservice, Accomodation microservice, Rating microservice. U nastavku će biti opisana svaka od navedenih komponenti.

### Arhitektura
![Dijagram](/Dijagrami/DijagramTokaPodataka.jpg)

Ovaj sistem predstavlja mikroservisnu arhitekturu. Zahtevi klijenta se putem API Gateway-a prosleđuju odgovarajućim mikroservisima. Svaki od ovhi servisa na osnovu svojih potreba ima posebnu bazu podataka. Mikroservisi takođe imaju i međusobne veze. Za razmenu fajlova između mikroservisa i klijenta koristi se SFTP server. Neki od mikroservisa imaju vezu sa eksternim servisom za plaćanje.

### Autentifikacija
Nakon zahteva korisnika da se prijavi na sistem API Gateway šalje zahtev servisu za autentifikaciju, dobija JWT token, i šalje ga nazad korisniku. Pri svakom narednom zahtevu korisnika, API Gateway šalje zahtev servisu za autentifikaciju kako bi token verifikovao, potom prosleđuje zahtev zajedno sa tokenom odgovarajućim servisima. Međuservisna komunikacija obezbeđena je korišćenjem mutual TLS-a. Prednosti korišćenja posebnog servisa za autentifikaciju naspram implementacije kompletne logike u API Gateway-u jeste da API Gateway više nije single point of failure. Mana je da je povećan latency u sistemu, jer sada API Gateway šalje dodatne pozive ka servisu za autentifikaciju.

### Autorizacija
Svaki servis ima svoju logiku za autorizaciju. Prednost ovakve implementacije jeste da servisi imaju veću kontrolu pri implementaciji kontrole pristupa. Mane su da servisi više ne obavljaju jednu stvar, već pored poslovne logike brinu i o autorizaciji. Pored toga, dolazi i do ponavljanja koda, odnosno ne poštuje se DRY princip.

## Klijentska aplikacija

### Opis
Klijentska aplikacija predstavlja vezu korisnika sa posmatranim sistemom. Omogućava kupovinu avionskih karata kao i rezervaciju smeštaja na destinaciji putovanja. Napredni algoritam preporuka klijentima će ponuditi najbolji smeštaj u skladu sa njihovim potrebama. Nakon boravka u objektu klijent može oceniti navedeni objekat i na taj način poboljšati naredne preporuke.

### Tehnologije
Ova aplikacija implementirana je kao web aplikacija u Angular radnom okviru. Komunikacija se obavlja putem REST protokola.

### Povezane komponente
Sve zahteve ova aplikacija šalje API Gateway-u u vidu REST poziva. API Gateway će taj poziv proslediti odgovarajućem mikroservisu i odgovor će u istom formatu vratiti klijentskoj aplikaciji, koja odgovor prikazuje klijentu u odgovarajućem formatu. 

S obzirom da ovu aplikaciju koriste i pravna lica, potrebno im je dostavljati fakture za kupovine. Razmena faktura obavlja se putem SFTP servera. Servisi fakture postavljaju na server, obaveštavaju klijenta da su fakture spremne, koji se onda kači na SFTP server i preuzima ih na svoj računar.

## API Gateway

### Opis
Uloga API Gateway-a je da od klijentske aplikacije prima REST poruke i da ih prosleđuje odgovarajućim servisima. Klijent se prvo mora ulogovati kako bi mogao da šalje zahteve ka servisima. API Gateway šalje zahtev servisu za autentifikaciju i vraća nazad JWT token korisniku. Nakon što je klijent ulogovan, sa svakim zahtevom šalje i dobijeni token.  Njegovi zahtevi prosleđivaće se odgovarajućem servisu. Svaki servis kome se zahtev prosledi posebno brine o kontroli pristupa.

### Tehnologije
API Gateway implementiraj je u .NET-u. Sa klijentskom aplikacijom komunicira putem REST protokola. Sa ostalim servisima komunicira putem gRPC-a, WCF-a ili GraphQL-a.

### Povezane komponente
Pored klijentske aplikacije, ovaj servis povezan je i sa mikroservisima kojima prosleđuje zahteve. Mora znati kako da komunicira sa svakim od ovih servisa s obzirom da koriste različite protokole za komunikaciju. Nakon što napravi i pošalje zahtev putem odgovarajućeg protokola, na isti način prima odgovor i vraća ga klijentsoj aplikaciji putem REST protokola.

## Airline Company Microservice

### Opis
Uloga Airline Company mikroservisa je kupovina karata za avionske letove. Servis pored fizičkih lica, podržava kupovinu i za pravna lica. Njima se fakture šalju na poseban server sa koga mogu da ih preuzmu. Za plaćanje je zadužen eksterni servis koji nakon uspešno obavljene transakcije obaveštava ovaj servis kako bi se klijentu potvrdila kupovina.

### Tehnologije
Servis je implementiran koristeći NodeJS radni okvir. Podaci su sačuvani u MongoDB NoSQL bazi podataka. Sa API Gateway-om kao i Accomodation servisom komunicira koristeći gRPC protokol, dok sa ekternim sistemom plaćanja komunicira putem REST protokola.

### Povezane komponente
Airline Company mikroservis sve klijentske zahteve prima od API Gateway-a, koje nakon obrade istim putem i vraća. Sve potrebne podatke čuva u MongoDB bazi podataka. Kako bi klijentu bio ponuđen smeštaj na destinaciji leta, ovaj servis povezan je i sa Accomodation mikroservisom. Plaćanje se obavlja putem eksternog servisa za plaćanje, dok se fakture pravnim licima postavljaju na SFTP server. 

## Accomodation Microservice

### Opis
Accomodation mikroservis služi za rezervaciju smeštaja. U saradnji sa Rating mikroservisom klijentima se na osnovu potreba i prethodnih ocena preporučuje odgovarajući smeštaj. Plaćanje se vrši putem eksternog servisa. Ovaj servis takođe podržava slanje faktura poslovnim korisnicima putem posebnog servera.

### Tehnologije
Ovaj servis implementiran je u kao WCF servis u .NET-u. Podatke čuva u MongoDB NoSQL bazi podataka. Takođe može primati i slati gRPC poruke za komunikaciju sa ostalim mikroservisima. Sa servisom za plaćanje komunicira putem REST protokola.

### Povezane komponente
Sve zahteve od klijentske aplikacije servis prima kroz API Gateway. Pored toga povezan je i sa Airline Company mikroservisom kako bi se klijentima ponudio smeštaj na destinaciji leta. Kako bi klijent dobio odgovarajuću preporuka smeštaja, postoji veza i sa Rating mikroservisom koji na osnovu ocena daje preporuke. Podaci su sačuvani u MongoDB bazi podatak. Plaćanje se vrši putem eksternog servisa, dok se fakture razmenjuju kroz SFTP server.

## Rating Microservice

### Opis
Uloga ovog servisa u sistemu je ocenjivanje kao i preporuka smeštaja. Nakon što klijent zatraži smeštaj, Accomodation servis će od Rating mikroservisa zahtevati preporuku na osnovu ocena i potreba klijenta. Klijent će nakon boravaka moći da oceni smeštaj što će se putem Rating servisa sačuvati i koristiti u daljim preporukama. 

### Tehnologije
Servis je implementiran u Spring Boot radnom okviru. Sa API Gateway-om komunicira putem GraphQL protokola, dok sa Accomodation mikroservisom poruke razmenjuje pomoću gRPC poruka.
Podaci o ocena sačuvani su u Neo4J graf bazi podataka.

### Povezane komponente
Ocene za smeštaje od klijenta primaju se preko API Gateway-a. Nakon prijema čuvaju se u Neo4J bazi. Preporuke na osnovu sačuvanih ocena servis na zahtev dostavlja Accomodation servisu.

## SFTP Server

### Opis
Uloga SFTP servera je dostavljanje faktura poslovnim korisnicima od strane Airline Company i Accomodation mikroservisa.

### Povezane komponente
Accomodation i Airline mikroservisi za poslovne korisnike mogu izdavati fakture. Ove fakture upload-uju na SFTP server kome klijenti pristupaju i preuzimaju ih.

# Reference
1) https://frontegg.com/blog/authentication-in-microservices
2) https://www.thirdrocktechkno.com/blog/authentication-authorization-in-a-microservices-architecture/
3) https://dev.to/behalf/authentication-authorization-in-microservices-architecture-part-i-2cn0
4) https://api7.ai/blog/understanding-microservices-authentication-services
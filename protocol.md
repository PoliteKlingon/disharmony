# posilani zprav:

ID jako 8 znaku + \0 - vzdycky 9
message type vzdy 1 byte - cislo 
pocet znaku user jako 4 byty - cislo
znaky user
pocet znaku room jako 4 byty - cislo
znaky room
time jako 8 znaku + \0 - vzdycky 9
pocet znaku content jako 4 byty - cislo
znaky content
4 byty magicnum

# navazani spojeni:
user posle prazdnou zpravu typu LOGIN, content je heslo, user a room vyplnene
server posle zpravu s contentem session_id typu LOGIN pokud passwd ok nebo novy user.
	zbytek zpravy prazdny, kdyz failne autorizace, posle LOGIN zpravu s prazdnym contentem.
user i server si se navzajem zapamatuji

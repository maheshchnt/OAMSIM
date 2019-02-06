oamsim: oam_cli.c oam_mep.c oam_tx.c
	gcc -o oamsim oam_cli.c oam_mep.c oam_tx.c -lpthread

.PHONY: clean

clean:
	rm -f oamsim

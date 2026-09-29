package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Multi-master (v12.21.0, design doc "Partie 2 — avance" §Multi-master) : un
// seul agent peut pousser vers PLUSIEURS Nginx Control independants (typique
// DMZ + LAN), chacun avec sa propre approbation/jeton — deux Nginx Control
// ne se connaissent jamais entre eux, donc deux identites d'agent distinctes,
// meme si c'est le meme processus qui les porte toutes les deux.
//
// targetConfig est une cible parmi la liste que --targets-file charge (voir
// loadTargetsFile ci-dessous et README.md). Le mode a une seule cible
// (--dashboard-url et les flags associes, tel qu'avant cette version) reste
// le chemin par defaut et continue de fonctionner a l'identique : il est
// traduit en interne en une liste d'une seule targetConfig au nom vide (voir
// main.go), donc les logs et le comportement d'un agent a une seule cible ne
// changent pas d'une virgule.
type targetConfig struct {
	Name               string `json:"name"`
	DashboardURL       string `json:"dashboardUrl"`
	StateFile          string `json:"stateFile"`
	TokenFile          string `json:"tokenFile,omitempty"`
	Token              string `json:"token,omitempty"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty"`
}

// loadTargetsFile lit le fichier JSON documente dans README.md, section
// "Multi-master" :
//
//	[
//	  {"name": "dmz", "dashboardUrl": "https://dmz.example.com", "stateFile": "/data/dmz-state.json", "tokenFile": "/data/dmz-token"},
//	  {"name": "lan", "dashboardUrl": "https://lan.internal",    "stateFile": "/data/lan-state.json",  "tokenFile": "/data/lan-token"}
//	]
//
// Chaque nom doit etre unique, non vide, et different de "all" (reserve —
// voir publishesTo() ci-dessous : "all" dans un label
// nginx-control.publish= signifie explicitement "toutes les cibles", jamais
// le nom d'une cible reelle). dashboardUrl et stateFile sont obligatoires
// pour chaque entree : aucune valeur par defaut devinee ici, une cible mal
// remplie doit echouer au demarrage plutot que de pousser silencieusement
// vers le mauvais Nginx Control (ou vers un fichier d'etat partage par
// accident avec une autre cible).
func loadTargetsFile(path string) ([]targetConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var targets []targetConfig
	if err := json.Unmarshal(data, &targets); err != nil {
		return nil, fmt.Errorf("JSON invalide : %w", err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("aucune cible declaree (tableau JSON vide)")
	}
	seen := map[string]bool{}
	for i := range targets {
		name := strings.ToLower(strings.TrimSpace(targets[i].Name))
		if name == "" {
			return nil, fmt.Errorf("cible #%d : \"name\" est requis", i+1)
		}
		if name == "all" {
			return nil, fmt.Errorf(`cible #%d : le nom "all" est reserve (il signifie "toutes les cibles" dans une etiquette nginx-control.publish=) et ne peut pas nommer une cible reelle`, i+1)
		}
		if seen[name] {
			return nil, fmt.Errorf("cible #%d : nom \"%s\" duplique", i+1, name)
		}
		seen[name] = true
		if targets[i].DashboardURL == "" {
			return nil, fmt.Errorf("cible #%d (%s) : \"dashboardUrl\" est requis", i+1, name)
		}
		if targets[i].StateFile == "" {
			return nil, fmt.Errorf("cible #%d (%s) : \"stateFile\" est requis", i+1, name)
		}
		targets[i].Name = name
		targets[i].DashboardURL = strings.TrimRight(targets[i].DashboardURL, "/")
	}
	// Fix v12.22.0 (audit finding BAS-GO-b, regression v12.21.0) : le
	// commentaire au-dessus de targetConfig annoncait deja que deux cibles
	// partageant le meme stateFile etaient refusees, mais rien ne le
	// verifiait — deux cibles pouvaient silencieusement s ecraser mutuellement
	// leur agentId et leur jeton persistes.
	seenStateFiles := map[string]string{}
	for i := range targets {
		if prevName, dup := seenStateFiles[targets[i].StateFile]; dup {
			return nil, fmt.Errorf("cibles \"%s\" et \"%s\" : meme \"stateFile\" (%s) — chaque cible doit avoir son propre fichier d etat", prevName, targets[i].Name, targets[i].StateFile)
		}
		seenStateFiles[targets[i].StateFile] = targets[i].Name
	}
	return targets, nil
}

// publishesTo decide si un conteneur portant l'etiquette
// nginx-control.publish=<liste> doit etre pousse vers la cible nommee
// targetName. `publish` vide/absente (nil) ou contenant "all" veut dire
// "toutes les cibles" — le comportement par defaut, identique a un agent qui
// n'a jamais entendu parler du multi-master (une seule cible, au nom vide,
// matche toujours). La comparaison est insensible a la casse (les deux cotes
// sont deja normalises en minuscules par splitCSV/loadTargetsFile, mais
// rester defensif ici ne coute rien).
func publishesTo(publish []string, targetName string) bool {
	// Fix v12.22.0 (audit finding BAS-GO-a, regression v12.21.0) : en mode
	// mono-cible, targetName vaut toujours "" (voir main.go, la seule
	// targetConfig construite depuis --dashboard-url a un Name vide) — il n y
	// a alors qu une seule cible possible, donc rien a filtrer. Sans ce
	// retour anticipe, un conteneur portant l etiquette
	// nginx-control.publish=lan (ecrite en prevision d un futur multi-master,
	// ou copiee d un autre projet) se retrouvait invisible pour cet agent-la,
	// contrairement a ce que le README et le commentaire ci-dessus annoncent
	// ("matche toujours" en mono-cible).
	if targetName == "" {
		return true
	}
	if len(publish) == 0 {
		return true
	}
	for _, p := range publish {
		if p == "all" || strings.EqualFold(p, targetName) {
			return true
		}
	}
	return false
}

// vhostEntry associe un VhostSpec (le type manifeste, mirroir exact du
// schema JSON cote dashboard — voir manifest.go) a la liste de cibles
// auxquelles le publier, lue depuis l'etiquette nginx-control.publish= du
// meme conteneur. Ce champ ne fait PAS partie du manifeste JSON envoye : il
// ne sert qu'a filtrer, cote agent, quelle cible reçoit quel vhost — ajouter
// un champ "publish" a VhostSpec lui-meme aurait pollue un type dont le
// commentaire d'en-tete (manifest.go) insiste justement sur le fait qu'il ne
// doit contenir que ce que le dashboard sait interpreter.
type vhostEntry struct {
	Vhost   VhostSpec
	Publish []string
}

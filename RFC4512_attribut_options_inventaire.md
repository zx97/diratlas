# Inventaire — Options d'attribut (RFC 4512 §2.5.2) et fonctions LDAP manquantes

Date : 2026-08-20
Contexte : DirAtlas v2.6.0 (Build #12 c9761d8)
Statut : **Analyse — à prioriser**

---

## 1. Menu dynamique du panneau Attributs (contexte de ce document)

Demande utilisateur : dans le panneau Attributs, **F2 doit ouvrir un menu dynamique**
(liste contextuelle des actions possibles sur l'attribut sous le curseur), pas seulement
l'édition inline. Le menu doit :
- n'afficher que les actions **autorisées par le schéma** pour l'attribut courant ;
- vérifier le schéma (subschema `attributeTypes`) AVANT de proposer les actions
  (ex. : dupliquer n'est proposé que si l'attribut est multi-valué / le schéma l'autorise).

Ceci nécessite d'ajouter un **parseur d'`attributeTypes`** du subschema (actuellement seuls
`objectClasses` sont parsés : `getMandatoryAttrs`, `listObjectClasses`, `loadOCSchema`).

---

## 2. RFC 4512 §2.5.2 — Attribute Options : état et ce qui manque

### Rappel du §2.5.2
Une **AttributeDescription** = `attributetype [; options]`, ex. :
- `description`
- `description;binary`
- `cn;lang-en`
- `jpegPhoto;binary;lang-fr`

Règles :
- options insensibles à la casse, préfixées par `;` ;
- option `binary` : valeurs encodées en OCTET STRING (BER), pas en chaîne ;
- options `lang-*` : sélecteurs de langue ;
- les options ne changent pas le **type** de l'attribut, seulement son **traitement** ;
- le serveur, en écrivant, utilise l'attribut sans options (le type de base) + l'option
  peut être renvoyée dans les descriptions d'attribut.

### Support actuel dans DirAtlas
| Aspect | Statut | Détails |
|--------|--------|---------|
| Affichage d'un attribut avec option (`cn;lang-en`) | ⚠️ Partiel | Le nom est affiché tel quel ; `lowerName` le minuscule mais ne découpe pas `;option` ; le formatage AD/ldapcore reçoit le nom complet avec `;...` → la correspondance de formatage échoue souvent |
| Écriture d'un attribut avec option | ⚠️ Non géré | `modifyAttribute`/`addAttribute` envoient le nom tel quel ; le serveur l'accepte mais DirAtlas ne sépare pas type/option |
| Édition des options | ❌ Aucune | Pas d'UI pour ajouter/retirer/modifier `;binary`, `;lang-*` |
| Option `binary` (décodage/encodage BER) | ❌ Aucune | `binaryAttributes` existe mais le déclenchement n'est pas basé sur l'option `;binary` |
| Options `lang-*` | ❌ Aucune | Pas de gestion des sélecteurs de langue |
| Tri / regroupement par attribut de base | ❌ Non | `cn;lang-en` et `cn;lang-fr` sont vus comme des attributs distincts, pas groupés sous `cn` |
| Recherche/filtre avec options | ❌ Non | Les filtres sont passés tels quels |

### Priorisation des travaux §2.5.2
1. **P0 — Parseur d'AttributeDescription** : découper `attributetype;option1;option2`
   en `(type, [options])`, insensible à la casse. Base de tout le reste.
2. **P0 — Affichage correct** : utiliser le type de base pour le formatage/les couleurs,
   afficher les options distinctement (ex. `cn;lang-en` surligné différemment).
3. **P1 — Édition des options** : dans le menu dynamique de l'attribut, proposer
   « Modifier les options » (ajouter/retirer `;binary`, `;lang-*`).
4. **P1 — Regroupement** : grouper les variantes (`cn;lang-en`, `cn;lang-fr`) sous le
   type de base `cn`, avec expansion/collapse.
5. **P2 — Option `binary`** : traiter `;binary` comme déclencheur du chemin binaire
   (`binaryAttributes` + formatage HEX/octet-stream) indépendamment du flavour.
6. **P2 — Écriture avec option** : séparer proprement type/option lors des écritures.

---

## 3. Inventaire des fonctions LDAP (RFC 4511 / libldap) — implémentées vs manquantes

### Déjà implémentées dans DirAtlas (src/ldap_conn.*)
| Opération | RFC | Fonction | Statut |
|-----------|-----|----------|--------|
| Bind simple | 4511 §4.2 | `simpleBind` | ✅ |
| Bind SASL (interactive) | 4511 §4.2 / 4422 | `saslBind` | ✅ |
| StartTLS | 4511 §4.14 | `startTLS` | ✅ |
| Search (+ paging RFC 2696) | 4511 §4.5 | `search` / `searchOne` | ✅ |
| Add | 4511 §4.7 | `addObject` | ✅ |
| Delete | 4511 §4.8 | `deleteObject` | ✅ |
| Modify (ADD/REPLACE/DELETE) | 4511 §4.6 | `addAttribute`, `modifyAttribute`, `deleteAttribute`, `deleteAttributeValue`, `replaceAttributeValue` | ✅ |
| ModifyDN (rename/move) | 4511 §4.9 | `renameObject` | ✅ |
| Who am I? | 4532 | `whoAmI` | ✅ |
| Password Modify | 3062 | `passwordModify` | ✅ |
| Cancel | 3909 | `cancelOperation` | ✅ |
| Extended operation générique | 4511 §4.12 | `extendedOp` | ✅ |
| Contrôles (user-supplied) | 4511 §4.1.11 | `addControl`, `addControlSpec` | ✅ |
| Unbind | 4511 §4.3 | destructeur (`ldap_unbind_ext`) | ✅ |

### NON implémentées (RFC 4511 et extensions)
| # | Opération | RFC | Utilité | Priorité |
|---|-----------|-----|---------|----------|
| 1 | **Compare** | 4511 §4.10 | Vérifier si une valeur d'attribut correspond ; utile pour « tester la présence » d'une option/valeur | **P0** |
| 2 | **Abandon** (public) | 4511 §4.11 | `cancelOperation` existe mais `abandon` d'un search en cours n'est pas exposé proprement | P1 |
| 3 | **Persistent Search** (RFC 4533) | 4533 | Notification de changements en temps réel | P2 |
| 4 | **Synchronization** | 4533 | Sync répliquée | P3 |
| 5 | **Refresh / Chaining** | — | Refresh de cache ; dépend des overlays | P3 |
| 6 | **Modify-Increment** | 4525 | `modify` avec `increment` (compteurs) | P2 |
| 7 | **Assertion control** | 4528 | Contrôle d'assertion | P2 |
| 8 | **Pre/Post-Read control** | 4527 | Lire valeurs avant/après modif | P2 |
| 9 | **Subentries** (RFC 3672) | 3672 | Gestion d'`entryDN`/sous-entrées opérationnelles | P3 |
| 10 | **RootDSE opérations spécifiques** | 4512 | Lecture plus fine des capabilities (`supportedCapabilities`, `supportedFeatures`) | P2 |

### Priorisation recommandée (à revoir ensemble)
- **P0** : `Compare` (simple, très utile pour valider/authentifier, et nécessaire pour
  le menu dynamique « tester une valeur »), plus le **parseur d'`attributeTypes`**
  (requis pour la duplication autorisée par schéma et pour §2.5.2).
- **P1** : `Abandon` propre, édition des options, regroupement des variantes.
- **P2** : `binary` handling, `Modify-Increment`, assertion/pre-post-read, persistent search.
- **P3** : sync, subentries, refresh/chaining.

---

## 4. Menu dynamique Attributs — spécification proposée

### Déclencheur
`F2` (et éventuellement clic droit) dans le panneau Attributs, sur la ligne sous le curseur.

### Actions candidates (affichées selon le schéma)
| Action | Condition d'affichage (schéma) |
|--------|--------------------------------|
| Éditer la valeur | Toujours |
| Modifier les options (RFC 4512 §2.5.2) | Toujours (si le type de base est connu) |
| Ajouter une valeur | Si l'attribut est **multi-valué** (`EQUALITY` non-SINGLE) ou inconnu |
| Dupliquer la valeur | Si multi-valué (schéma l'autorise) |
| Supprimer la valeur | Si multi-valué (et pas RDN unique) |
| Supprimer l'attribut | Toujours (sauf attributs obligatoires / opérationnels protégés) |

### Données nécessaires (à implémenter)
1. **Parseur d'`attributeTypes`** du subschema → par attribut : `SINGLE-VALUE` ?,
   `EQUALITY`/`ORDERING`/`SUBSTR` (pour l'unicité), `SYNTAX`, `NO-USER-MODIFICATION`.
2. **Parseur d'`AttributeDescription`** (RFC 4512 §2.5.2) → `(type, options)`.
3. Chemin de lecture : `subschemaSubentry` (RootDSE) → `attributeTypes` (subschema).

### Vérification avant duplication
- L'attribut cible est-il défini dans le subschema ?
  - non → proposer uniquement Édition (schéma inconnu → prudence) + message ;
  - oui et `SINGLE-VALUE` → pas de duplication/ajout de valeur ;
  - oui et multi-valué → proposer Ajouter/Dupliquer/Supprimer valeur.

---

## 5. Fichiers impactés (ordre de travail)
1. `src/ldapcore/attrs.h/.cpp` (ou nouveau `src/ldapcore/attrdesc.h/.cpp`) :
   parseur d'AttributeDescription (type + options).
2. `src/tui/attrs.cpp` : parseur d'`attributeTypes` + fonction « est multi-valué / autorise X ».
3. `src/tui/app.cpp` : menu dynamique F2 (remplace l'édition inline directe).
4. `src/ldap_conn.cpp` : `compare()` (P0) si retenu.

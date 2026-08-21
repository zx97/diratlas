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
| Parseur d'AttributeDescription | ✅ Fait | `ldapcore/attrdesc` : `type;opt1;opt2`, insensible à la casse, détecte `binary`, OID (commit `0181068`) |
| Affichage d'un attribut avec option (`cn;lang-en`) | ✅ Fait | Le type de base est utilisé pour le formatage/les couleurs ; les options restent affichées dans le nom |
| Écriture d'un attribut avec option | ✅ Fait | `addAttribute`/`modifyAttribute` envoient le nom complet (type+options) ; `appAttrOptions` permet de renommer type/options |
| Édition des options | ✅ Fait | Menu F2 → « Modify attribute options » (RFC 4512 §2.5.2) |
| Regroupement par attribut de base | ✅ Fait | Les variantes (`cn;lang-en`, `cn;lang-fr`) sont groupées sous le type de base `cn` |
| Vérification schéma à l'ajout d'attribut | ✅ Fait | `appAddAttr` refuse un attribut non autorisé par les objectClass de l'entrée ; pour `objectClass`, vérifie que la classe existe et signale les MUST manquants |
| Option `binary` (décodage/encodage BER) | ⚠️ Partiel | L'option `;binary` est reconnue par le parseur ; le déclenchement du chemin binaire via l'option reste à brancher |
| Options `lang-*` | ⚠️ Partiel | Parsées et regroupées ; aucune logique de langue côté client |
| Recherche/filtre avec options | ⚠️ Non | Les filtres sont passés tels quels (aucun préfixage d'option) |

### Priorisation des travaux §2.5.2 (mis à jour)
1. ✅ **Fait — Parseur d'AttributeDescription** : `ldapcore/attrdesc`.
2. ✅ **Fait — Affichage correct** : type de base pour le formatage ; options affichées.
3. ✅ **Fait — Édition des options** : menu F2 → « Modify attribute options ».
4. ✅ **Fait — Regroupement** : variantes groupées sous le type de base.
5. ⏳ **P2 — Option `binary`** : brancher `;binary` comme déclencheur du chemin binaire
   (`binaryAttributes` + formatage HEX/octet-stream) indépendamment du flavour.
6. ⏳ **P2 — Écriture avec option** : confirmation/validation des options avant écriture.

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
| 1 | **Abandon** (public) | 4511 §4.11 | `cancelOperation` existe mais `abandon` d'un search en cours n'est pas exposé proprement | P1 |
| 2 | **Persistent Search** (RFC 4533) | 4533 | Notification de changements en temps réel | P2 |
| 3 | **Synchronization** | 4533 | Sync répliquée | P3 |
| 4 | **Refresh / Chaining** | — | Refresh de cache ; dépend des overlays | P3 |
| 5 | **Modify-Increment** | 4525 | `modify` avec `increment` (compteurs) | P2 |
| 6 | **Assertion control** | 4528 | Contrôle d'assertion | P2 |
| 7 | **Pre/Post-Read control** | 4527 | Lire valeurs avant/après modif | P2 |
| 8 | **Subentries** (RFC 3672) | 3672 | Gestion d'`entryDN`/sous-entrées opérationnelles | P3 |
| 9 | **RootDSE opérations spécifiques** | 4512 | Lecture plus fine des capabilities (`supportedCapabilities`, `supportedFeatures`) | P2 |

### Priorisation recommandée (mis à jour)
- ✅ **Fait — Compare** (RFC 4511 §4.10) : `LDAPConn::compare()`.
- ✅ **Fait — Parseur d'`attributeTypes`** : `AttrSchemaInfo` + `loadAttrSchema`.
- ✅ **Fait — Menu dynamique F2** : contextuel selon le schéma.
- ✅ **Fait — Vérification schéma à l'ajout d'attribut** : `getAllowedAttrs` (MUST∪MAY hérités).
- **P1** : `Abandon` propre.
- **P2** : `binary` handling, `Modify-Increment`, assertion/pre-post-read, persistent search.
- **P3** : sync, subentries, refresh/chaining.

---

## 4. Menu dynamique Attributs — implémenté

### Déclencheur
`F2` (et `appPickList`) dans le panneau Attributs, sur la ligne sous le curseur.

### Actions candidates (affichées selon le schéma) — implémentées
| Action | Condition d'affichage (schéma) | Statut |
|--------|--------------------------------|--------|
| Éditer la valeur | Toujours | ✅ |
| Modifier les options (RFC 4512 §2.5.2) | Si l'attribut a des options | ✅ |
| Ajouter une valeur | Si l'attribut est **multi-valué** et non `NO-USER-MODIFICATION` | ✅ |
| Dupliquer la valeur | Si multi-valué + une valeur sélectionnée | ✅ |
| Supprimer la valeur | Si multi-valué + une valeur sélectionnée | ✅ |
| Supprimer l'attribut | Toujours (sauf protégé) | ✅ |

### Vérification avant ajout d'attribut (implémentée dans `appAddAttr`)
- **Attribut ≠ objectClass** : doit être dans l'union MUST∪MAY (héritée via SUP) des
  objectClass de l'entrée, sinon refus avec explication (`getAllowedAttrs`).
- **objectClass** : la classe doit exister dans le schéma (sinon refus) ; les MUST de la
  nouvelle classe absents de l'entrée sont signalés.

---

## 5. Fichiers impactés (ordre de travail)
1. `src/ldapcore/attrdesc.h/.cpp` : parseur d'AttributeDescription (type + options). ✅
2. `src/tui/attrs.cpp` : parseur d'`attributeTypes` (`AttrSchemaInfo`/`loadAttrSchema`),
   `parseMAY`, `getAllowedAttrs` (MUST∪MAY hérités). ✅
3. `src/tui/app.cpp` : menu dynamique F2, `appAttrMenu`, `appAttrDuplicateValue`,
   `appAttrOptions`, vérification schéma dans `appAddAttr`. ✅
4. `src/ldap_conn.cpp/.h` : `compare()` (RFC 4511 §4.10). ✅

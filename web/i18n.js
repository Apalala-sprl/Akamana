/* Traduction de l'interface.
 *
 * Akamana n'avait aucun mécanisme de langue : setLang() posait une variable
 * que rien ne relisait, et le markup ne portait aucun point d'ancrage. Plutôt
 * que d'annoter les 600 et quelques chaînes de index.html une par une — une
 * réécriture massive du markup, donc un risque de régression massif — la
 * traduction se fait ici, à la volée, en indexant sur le texte anglais.
 *
 * Conséquences assumées de ce choix :
 *   — une chaîne anglaise donnée n'a qu'une seule traduction, quel que soit
 *     l'endroit où elle apparaît ;
 *   — une chaîne absente du dictionnaire reste en anglais, sans casser quoi
 *     que ce soit. La couverture peut donc grandir par simple ajout de données.
 *
 * Le texte anglais d'origine est mémorisé au premier passage, sinon repasser
 * en anglais serait impossible.
 */
(function () {
  "use strict";

  const DICT = Object.create(null);   // rempli plus bas par i18nAjouter()
  const ATTRS = ["placeholder", "title", "aria-label"];

  // Ne jamais toucher au contenu de ces éléments : du code, des commandes et
  // des identifiants s'y affichent, et « Name » y est une clé, pas un mot.
  const OPAQUES = new Set(["SCRIPT", "STYLE", "CODE", "PRE", "TEXTAREA", "SVG"]);

  // Texte anglais d'origine, par nœud. WeakMap : rien à nettoyer quand le
  // rendu remplace un sous-arbre.
  const origineTexte = new WeakMap();
  const origineAttr = new WeakMap();

  let langue = "en";
  let observateur = null;

  function traduire(s) {
    // Le markup est indenté : un paragraphe sur plusieurs lignes contient des
    // retours à la ligne et des espaces qui n'ont rien à voir avec la phrase.
    // La clé est donc la phrase à espaces normalisés, sinon aucune phrase
    // longue ne pourrait jamais correspondre.
    const clef = s.trim().replace(/\s+/g, " ");
    if (!clef) return null;
    const fr = DICT[clef];
    if (!fr) return null;
    // On restitue l'espacement de bord d'origine, qui sépare le texte des
    // balises voisines.
    const avant = s.match(/^\s*/)[0];
    const apres = s.match(/\s*$/)[0];
    return avant + fr + apres;
  }

  function opaque(node) {
    for (let p = node.parentNode; p && p.nodeType === 1; p = p.parentNode) {
      if (OPAQUES.has(p.tagName)) return true;
      if (p.dataset && p.dataset.i18n === "off") return true;
    }
    return false;
  }

  function peindreTexte(node) {
    if (opaque(node)) return;
    if (!origineTexte.has(node)) {
      if (!node.nodeValue.trim()) return;
      origineTexte.set(node, node.nodeValue);
    }
    const en = origineTexte.get(node);
    if (langue === "en") {
      if (node.nodeValue !== en) node.nodeValue = en;
      return;
    }
    const fr = traduire(en);
    if (fr && node.nodeValue !== fr) node.nodeValue = fr;
  }

  function peindreAttrs(elem) {
    if (OPAQUES.has(elem.tagName)) return;
    let memo = origineAttr.get(elem);
    for (const a of ATTRS) {
      if (!elem.hasAttribute(a)) continue;
      if (!memo) { memo = Object.create(null); origineAttr.set(elem, memo); }
      if (!(a in memo)) memo[a] = elem.getAttribute(a);
      const en = memo[a];
      const cible = langue === "en" ? en : (traduire(en) || en);
      if (elem.getAttribute(a) !== cible) elem.setAttribute(a, cible);
    }
  }

  function parcourir(racine) {
    if (racine.nodeType === 3) { peindreTexte(racine); return; }
    if (racine.nodeType !== 1) return;
    if (OPAQUES.has(racine.tagName)) return;
    peindreAttrs(racine);
    const it = document.createTreeWalker(racine, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT);
    let n;
    while ((n = it.nextNode())) {
      if (n.nodeType === 3) peindreTexte(n);
      else peindreAttrs(n);
    }
  }

  function peindreTout() {
    parcourir(document.body);
    document.documentElement.lang = langue;
  }

  // L'application re-rend des pans entiers du DOM à chaque navigation. Sans
  // observateur, tout contenu produit après la bascule reviendrait en anglais.
  function observer() {
    if (observateur) return;
    observateur = new MutationObserver((lots) => {
      if (langue === "en") return;
      observateur.disconnect();
      for (const lot of lots) {
        for (const n of lot.addedNodes) parcourir(n);
        if (lot.type === "characterData") peindreTexte(lot.target);
      }
      observateur.observe(document.body, OPTIONS_OBS);
    });
    observateur.observe(document.body, OPTIONS_OBS);
  }
  const OPTIONS_OBS = { childList: true, subtree: true, characterData: true };

  window.i18n = {
    /** Ajoute ou complète le dictionnaire français. */
    ajouter(entrees) { Object.assign(DICT, entrees); },
    /** Nombre de chaînes connues — utile aux contrôles. */
    taille() { return Object.keys(DICT).length; },
    langue() { return langue; },
    appliquer(l) {
      langue = l === "fr" ? "fr" : "en";
      peindreTout();
      observer();
      return langue;
    },
  };
})();

/**
 * MHPanel Modular i18n Async Loader
 * Lightweight (~3KB) entry point for multi-language translations.
 * Automatically loads the required language bundle on demand.
 */
window.I18N_TRANSLATIONS = window.I18N_TRANSLATIONS || {};
window._i18nMaps = window._i18nMaps || {
    fa: new Map(), en: new Map(), ru: new Map(), ar: new Map(),
    it: new Map(), es: new Map(), zh: new Map(), de: new Map()
};

window._loadedLanguages = window._loadedLanguages || new Set();

function buildI18nMapForLang(l) {
    if (!window._i18nMaps[l]) window._i18nMaps[l] = new Map();
    const d = window.I18N_TRANSLATIONS[l];
    if (!d) return;
    const m = window._i18nMaps[l];
    for (const [k, v] of Object.entries(d)) {
        if (typeof v === "string") {
            m.set(v, k);
            const norm = v.trim().replace(/\u200c/g, " ").replace(/\s+/g, " ");
            if (norm !== v) m.set(norm, k);
        }
    }
}

window.loadLanguage = function(lang, callback) {
    if (!lang) lang = "fa";
    if (window._loadedLanguages.has(lang) && window.I18N_TRANSLATIONS[lang]) {
        if (typeof callback === "function") callback(window.I18N_TRANSLATIONS[lang]);
        return Promise.resolve(window.I18N_TRANSLATIONS[lang]);
    }

    return new Promise((resolve, reject) => {
        const script = document.createElement("script");
        script.src = `/static/js/i18n/${lang}.js?v=2.2`;
        script.async = true;
        script.onload = () => {
            window._loadedLanguages.add(lang);
            buildI18nMapForLang(lang);
            if (typeof callback === "function") callback(window.I18N_TRANSLATIONS[lang]);
            resolve(window.I18N_TRANSLATIONS[lang]);
        };
        script.onerror = (err) => {
            console.warn(`[i18n] Failed to load language pack: ${lang}`, err);
            if (typeof callback === "function") callback(null);
            reject(err);
        };
        document.head.appendChild(script);
    });
};

window.t = function(keyOrText, fallback = "") {
    if (!keyOrText) return "";
    const lang = localStorage.getItem("panel_language") || "fa";
    const dict = (window.I18N_TRANSLATIONS && window.I18N_TRANSLATIONS[lang]) || {};
    const faDict = (window.I18N_TRANSLATIONS && window.I18N_TRANSLATIONS.fa) || {};
    const enDict = (window.I18N_TRANSLATIONS && window.I18N_TRANSLATIONS.en) || {};
    const maps = window._i18nMaps || {};

    // 1. Direct key match in target dictionary
    if (dict[keyOrText] !== undefined) return dict[keyOrText];

    const clean = typeof keyOrText === "string" ? keyOrText.trim() : keyOrText;
    const norm = typeof keyOrText === "string" ? clean.replace(/\u200c/g, " ").replace(/\s+/g, " ") : keyOrText;

    // 2. Direct key match in normalized clean key
    if (dict[clean] !== undefined) return dict[clean];
    if (dict[norm] !== undefined) return dict[norm];

    if (lang === "fa") {
        for (const [l, m] of Object.entries(maps)) {
            if (l === "fa" || !m) continue;
            let k = m.get(clean) || m.get(norm);
            if (k && faDict[k]) return faDict[k];
        }
        if (faDict[keyOrText] !== undefined) return faDict[keyOrText];
        return fallback || keyOrText;
    }

    // Target is NOT Persian (en, ru, ar, it, es, zh, de):
    const faMap = maps.fa;
    let k = faMap ? (faMap.get(clean) || faMap.get(norm)) : null;
    if (k) {
        if (dict[k] !== undefined) return dict[k];
        if (enDict[k] !== undefined) return enDict[k];
    }

    const enMap = maps.en;
    let ek = enMap ? (enMap.get(clean) || enMap.get(norm)) : null;
    if (ek) {
        if (dict[ek] !== undefined) return dict[ek];
    }

    if (enDict[keyOrText] !== undefined) return enDict[keyOrText];
    if (enDict[clean] !== undefined) return enDict[clean];
    if (enDict[norm] !== undefined) return enDict[norm];

    // Dynamic replacements fallback
    if (window.DYNAMIC_REPLACEMENTS && window.DYNAMIC_REPLACEMENTS[lang]) {
        let updated = clean;
        for (const [re, rep] of window.DYNAMIC_REPLACEMENTS[lang]) {
            updated = updated.replace(re, rep);
        }
        if (lang === "en") {
            updated = updated.replace(/[۰-۹]/g, function(d) { return "۰۱۲۳۴۵۶۷۸۹".indexOf(d); })
                             .replace(/[٠-٩]/g, function(d) { return "٠١٢٣٤٥٦٧۸۹".indexOf(d); });
        }
        if (updated !== clean) return updated;
    }

    return fallback || keyOrText;
};

// Auto-bootstrap active language bundle
(function() {
    const activeLang = localStorage.getItem("panel_language") || "fa";
    if (activeLang !== "fa") {
        window.loadLanguage(activeLang).then(() => {
            if (typeof applyLanguage === "function") applyLanguage(activeLang);
        });
    } else {
        // Defer Persian bundle load to idle time so core UI renders instantly
        const idleLoad = window.requestIdleCallback || function(cb) { setTimeout(cb, 1200); };
        idleLoad(() => {
            window.loadLanguage("fa");
        });
    }
})();

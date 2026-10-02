'use strict';
/**
 * Règles d'analyse : aides du formulaire (page Analyse → Règles).
 *
 * Le stockage ne change pas : le YAML des règles personnalisées reste celui de
 * l'analyzer (GET/POST /api/analyzer/rules/custom, features/analyzer.js). Ces
 * deux routes ne font que préparer le formulaire :
 *
 *   GET  /api/analyzer/rules/templates?lang=   catalogue de modèles par application
 *   POST /api/analyzer/rules/to-yaml           { rules } -> { ok, yaml, errors }
 *                                              validation + YAML canonique (aucune écriture)
 *
 * Lecture seule (view_configs) : l'enregistrement passe par la route existante,
 * qui exige la permission deploy.
 */

const httpLib   = require('../lib/http');
const auth      = require('../lib/auth');
const templates = require('../lib/rule-templates');
const yamlOut   = require('../lib/rule-yaml-out');

const { PERMS, hasPerm } = auth;
const { send, parseBody } = httpLib;

function register(router) {
  router.get('/api/analyzer/rules/templates', async ({ res, session, url }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    return send(res, 200, { packs: templates.listTemplates(url.searchParams.get('lang') === 'en' ? 'en' : 'fr') });
  });

  router.post('/api/analyzer/rules/to-yaml', async ({ req, res, session }) => {
    if (!hasPerm(session, PERMS.VIEW_CONFIGS)) return httpLib.forbidden(res);
    const body = await parseBody(req);
    const { rules, errors } = yamlOut.normalizeRules(body && body.rules);
    if (errors.length) return send(res, 200, { ok: false, errors });
    return send(res, 200, { ok: true, yaml: yamlOut.rulesToYaml(rules), count: rules.length });
  });
}

module.exports = { register };

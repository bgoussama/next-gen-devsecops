# Contribuer au projet Next-Gen DevSecOps

## Workflow Git

1. Cloner le repo : `git clone https://github.com/oussama-bagy/next-gen-devsecops.git`
2. Créer une branche : `git checkout -b feat/nom-de-la-feature`
3. Développer avec des commits réguliers
4. Ouvrir une Pull Request vers `develop`

## Conventions de branches

```
main          → code production-ready, jamais de commit direct
develop       → branche d'intégration

feat/         → nouvelle fonctionnalité
fix/          → correction de bug
security/     → correctif de sécurité (priorité maximale)
chore/        → maintenance (deps, config)
docs/         → documentation uniquement
test/         → ajout ou correction de tests
```

## Conventions de commits (Conventional Commits)

Format : `type(scope): description courte`

```
feat(backend): add Groq API client with retry logic
fix(security): patch regex for base64 obfuscation detection
security(prompt): add LLM Guard semantic scanner
docs(readme): update environment variables table
chore(deps): upgrade fastapi to 0.115.0
test(security): add injection payload test cases
```

Règles :
- Impératif, minuscules
- Max 72 caractères
- Corps du commit (optionnel) : expliquer le POURQUOI, pas le QUOI

## Standards de code

- Python : formatter `black`, linter `ruff`
- Tous les nouveaux modules doivent avoir des tests unitaires
- Zéro secret dans le code — utiliser `.env` et `os.getenv()`
- Chaque fichier de sécurité doit avoir un commentaire `# [SECURITY]` expliquant la menace couverte

## Checklist PR

- [ ] Tests unitaires ajoutés et passent
- [ ] Pas de secrets dans le code
- [ ] Commentaires pédagogiques sur les décisions techniques
- [ ] `.env.example` mis à jour si nouvelles variables ajoutées

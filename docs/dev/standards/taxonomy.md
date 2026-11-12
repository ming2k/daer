# Documentation Taxonomy & Information Architecture

This document defines the organization, scope boundaries, and classification of documentation assets in a repository.

---

## 1. The Four-Quadrant System (Diátaxis)

Public documentation in `docs/` follows the Diátaxis information architecture:

```text
               PRACTICAL                   THEORETICAL
          ┌─────────────────────────┬─────────────────────────┐
          │  Tutorials              │  How-To Guides          │
LEARNING  │  (Learning-Oriented)    │  (Task-Oriented)        │
          │  `docs/tutorials/`      │  `docs/how-to/`         │
          ├─────────────────────────┼─────────────────────────┤
          │  Reference              │  Explanation            │
WORKING   │  (Information-Oriented) │  (Understanding-Orient) │
          │  `docs/reference/`      │  `docs/explanation/`    │
          └─────────────────────────┴─────────────────────────┘
```

- **`docs/tutorials/`**: Guided, hands-on lessons taking a new user through their first successful experience. Focuses on learning and building confidence.
- **`docs/how-to/`**: Step-by-step problem-solving recipes for specific goals. Focuses on accomplishing a practical task such as deployment or troubleshooting.
- **`docs/reference/`**: Technical descriptions of configuration options, command flags, schemas, and ABIs without tutorial prose. Focuses on precision and completeness.
- **`docs/explanation/`**: Conceptual deep dives, design rationale, and background discussions. Focuses on understanding the system and its architecture.

---

## 2. Documentation Spaces & Audiences

Documentation is structured into two surfaces separated by a one-way visibility boundary:

```text
┌─────────────────────────────────────────────────────────────┐
│ Public Surface (Users, Integrators, Operators)              │
│ `docs/tutorials/`, `how-to/`, `reference/`, `explanation/`  │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               │ Scope Boundary: public docs must
                               │ never link into the internal space.
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Engineering Surface (Contributors, Maintainers, Agents)     │
│ `docs/dev/` (internals, standards, roadmap, test plans)     │
│ `docs/adr/` (canonical architectural decision records)      │
└─────────────────────────────────────────────────────────────┘
```

1. **User/Operator Surface**: Addressed to end users and system administrators. Emphasizes operational workflows, configuration contracts, and deployment recipes.
2. **Engineering Surface**: Addressed to contributors, maintainers, and development agents. Emphasizes internal subsystem blueprints, verification test plans, and development standards.
3. **Audience Firewall**: Public documentation surfaces (`docs/{tutorials,how-to,reference,explanation}/`) must never link into the internal maintainer space (`docs/dev/**`). Links into `docs/adr/` remain permitted.
4. **Reverse Linking Permitted**: Internal documents may freely link outward to public reference and how-to guides.
5. **Neutral Standards**: The standards suite is project-independent. Repository-specific blueprints, test plans, and invariant registries belong in `docs/dev/` as project documents, not in `docs/dev/standards/`.

---

## 3. Directory Cleanliness

To keep the documentation tree clean, professional, and clutter-free, no loose `.md` files reside directly in `docs/`. All documentation must reside within one of the six canonical top-level directories:

- `docs/tutorials/`
- `docs/how-to/`
- `docs/reference/`
- `docs/explanation/`
- `docs/adr/`
- `docs/dev/`

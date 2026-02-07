# Detection Engineering Skills Hub

A collection of LLM agent skills for automated malware detection—from VirusTotal lookups to YARA rule generation.

## 🌐 Live Website

**Visit the hub:** https://yarahq.github.io/detection-engineering-site/

The website showcases all detection engineering skills with:
- Interactive skills grid with links to repositories
- Pipeline visualization (Hash → Sample → YARA Rule)
- Feature highlights and capabilities
- Light blue theme matching the detection engineering aesthetic

## 🎯 What This Is

This repository hosts the GitHub Pages site for the YARA HQ Detection Engineering skill ecosystem. It serves as a central hub linking to all skills that work together to create a complete detection engineering pipeline:

```
VirusTotal → Download → yarGen → YARA Expert → Production Rule
```

## 📦 Skills in the Ecosystem

| Skill | Repository | Purpose |
|-------|------------|---------|
| **Detection Engineering** | [detection-engineering-skill](https://github.com/YARAHQ/detection-engineering-skill) | Meta-skill orchestrating the full pipeline |
| **VirusTotal API** | [virustotal-api-skill](https://github.com/YARAHQ/virustotal-api-skill) | Threat intel, file downloads, hunting |
| **yarGen** | [yargen-go-skill](https://github.com/YARAHQ/yargen-go-skill) | YARA rule generation from malware samples |
| **YARA Rule Expert** | [yara-rule-skill](https://github.com/YARAHQ/yara-rule-skill) | Quality checks and rule optimization |

## 🚀 Quick Start

Install all skills to your OpenClaw environment:

```bash
# Detection Engineering (meta-skill)
git clone https://github.com/YARAHQ/detection-engineering-skill.git ~/.openclaw/skills/detection-engineering

# VirusTotal API
git clone https://github.com/YARAHQ/virustotal-api-skill.git ~/.openclaw/skills/virustotal-api

# yarGen
git clone https://github.com/YARAHQ/yargen-go-skill.git ~/.openclaw/skills/yargen

# YARA Rule Expert (packaged)
curl -L https://github.com/YARAHQ/yara-rule-skill/releases/latest/download/yara-rule-skill.skill -o ~/.openclaw/skills/yara-rule-skill.skill
```

## 🏗️ Website Structure

- `index.html` - Complete single-page website with embedded CSS
- No build process required - pure HTML/CSS
- GitHub Pages automatically deploys from `main` branch

## 📝 License

See [LICENSE](LICENSE) file for details.

## 🤝 Contributing

This site is part of the [YARA HQ](https://github.com/YARAHQ) ecosystem. Contributions welcome!

---

**Part of the YARA HQ detection engineering toolchain.**

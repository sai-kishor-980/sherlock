import json
import sys
from pathlib import Path

# Windows console encoding
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

BACKEND_DIR = Path(__file__).resolve().parent
SHERF_DIR = BACKEND_DIR.parent

adapters_dir = BACKEND_DIR / "app" / "models" / "adapters"
zip_pkg_base = SHERF_DIR / "Cybersecurity_Qwen3_QLoRA_Package.zip"
zip_pkg_models = SHERF_DIR / "models.zip"

print("=" * 80)
print("AGENTIC SHERLOCK AI - VERIFIED MODEL TRAINING ARTIFACTS")
print("=" * 80)

print(f"\n1. Source Package Archives:")
print(f"   - Base Cybersecurity QLoRA Zip: {zip_pkg_base.resolve()} (Size: {round(zip_pkg_base.stat().st_size / (1024*1024), 2)} MB)")
print(f"   - Domain Models Zip:            {zip_pkg_models.resolve()} (Size: {round(zip_pkg_models.stat().st_size / (1024*1024), 2)} MB)")

print(f"\n2. Extracted Trained Adapters & Checkpoints under {adapters_dir.resolve()}:\n")

if adapters_dir.exists():
    for item in sorted(adapters_dir.iterdir()):
        if not item.is_dir():
            continue
        print("-" * 70)
        print(f"ADAPTER DOMAIN / ROLE: [{item.name.upper()}]")
        configs = list(item.rglob("adapter_config.json"))
        if not configs:
            print("  No adapter_config.json found.")
            continue
        for cfg in configs:
            rel = cfg.relative_to(item)
            try:
                with open(cfg, "r", encoding="utf-8") as f:
                    cdata = json.load(f)
            except Exception as e:
                print(f"  Error reading {cfg}: {e}")
                continue

            parent = cfg.parent
            weights = list(parent.glob("*.safetensors")) + list(parent.glob("*.bin"))
            w_info = ", ".join([f"{w.name} ({round(w.stat().st_size / (1024*1024), 2)} MB)" for w in weights])

            print(f"  Directory:       {parent.resolve()}")
            print(f"  Config File:     {cfg.name}")
            print(f"  Base Foundation: {cdata.get('base_model_name_or_path')}")
            print(f"  Model Type:      {cdata.get('peft_type', 'LORA')} ({cdata.get('task_type', 'CAUSAL_LM')})")
            print(f"  LoRA Rank (r):   {cdata.get('r')}")
            print(f"  LoRA Alpha:      {cdata.get('lora_alpha')}")
            print(f"  LoRA Dropout:    {cdata.get('lora_dropout')}")
            print(f"  Target Modules:  {cdata.get('target_modules')}")
            print(f"  Weights File(s): {w_info or 'Weight tensors stored in source archive'}")

            # Check trainer_state.json
            t_state = parent / "trainer_state.json"
            if t_state.exists():
                try:
                    with open(t_state, "r", encoding="utf-8") as tf:
                        sdata = json.load(tf)
                    print(f"  Trained Epochs:  {sdata.get('epoch')}")
                    print(f"  Global Steps:    {sdata.get('global_step')}")
                    log_history = sdata.get("log_history", [])
                    if log_history:
                        losses = [h.get("loss") for h in log_history if "loss" in h]
                        if losses:
                            print(f"  Loss Trajectory: Initial={losses[0]:.4f} -> Final={losses[-1]:.4f}")
                except Exception as ex:
                    pass

            # Check README.md
            readme = parent / "README.md"
            if readme.exists():
                try:
                    with open(readme, "r", encoding="utf-8", errors="replace") as rf:
                        first_lines = [line.strip() for line in rf.readlines() if line.strip()][:3]
                        print(f"  README Details:  {' | '.join(first_lines)}")
                except Exception:
                    pass
            print()

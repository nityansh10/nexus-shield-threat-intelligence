# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  NEXUS-SHIELD — Real Fine-Tuning Script                                 ║
# ║  Run this in Google Colab (Runtime → Change runtime type → T4 GPU)      ║
# ║  Each section marked  ── CELL N ──  is one Colab cell.                  ║
# ╚══════════════════════════════════════════════════════════════════════════╝

# ── CELL 1 ──  Install all dependencies  (run once, then restart runtime)
"""
!pip install -q transformers==4.44.2 peft==0.12.0 bitsandbytes==0.43.3 \
             trl==0.10.1 accelerate==0.34.2 datasets==3.0.0 huggingface_hub
"""

# ── CELL 2 ──  Log in to Hugging Face
# Get your token at: https://huggingface.co/settings/tokens
# Create a token with WRITE permission.
"""
from huggingface_hub import login
HF_TOKEN = "hf_YOUR_TOKEN_HERE"   # <-- paste your token here
login(token=HF_TOKEN)
print("Logged in to Hugging Face.")
"""

# ── CELL 3 ──  Upload nexus_data.jsonl
# In Colab: click the folder icon on the left → upload nexus_data.jsonl
# Then run this cell to verify it loaded correctly.
"""
import json

with open("nexus_data.jsonl", "r") as f:
    raw = [json.loads(line) for line in f]

print(f"Loaded {len(raw)} training examples.")
print("Sample:", json.dumps(raw[0], indent=2)[:300])
"""

# ── CELL 4 ──  Format dataset for Phi-3 chat template
"""
from datasets import Dataset

SYSTEM_PROMPT = (
    "You are NEXUS-SHIELD, a cybersecurity incident classification engine. "
    "Analyze the security log and output ONLY a JSON object with exactly three fields: "
    "vector_class, target_infrastructure, and base_posture. No explanation. No markdown. "
    "Only the JSON object.\n\n"
    "Allowed vector_class values: BRUTE_FORCE_ATTEMPT, DATA_EXFILTRATION, "
    "ENDPOINT_COMPROMISE, RANSOMWARE_DEPLOYMENT, INSIDER_THREAT, "
    "FINANCIAL_SYSTEM_COMPROMISE, MALICIOUS_ANOMALY_UNKNOWN\n"
    "Allowed base_posture values: CONTAINMENT_MODE, ISOLATION_POSTURE, "
    "CREDENTIAL_REVOCATION, CRITICAL_CREDENTIAL_REVOCATION_REQUIRED"
)

def format_example(ex):
    return {
        "text": (
            f"<|system|>\n{SYSTEM_PROMPT}<|end|>\n"
            f"<|user|>\n{ex['input']}<|end|>\n"
            f"<|assistant|>\n{ex['output']}<|end|>"
        )
    }

formatted = [format_example(ex) for ex in raw]
dataset = Dataset.from_list(formatted)
dataset = dataset.train_test_split(test_size=0.05, seed=42)

print(f"Train: {len(dataset['train'])}  |  Val: {len(dataset['test'])}")
print("\nSample formatted text:")
print(dataset['train'][0]['text'][:400])
"""

# ── CELL 5 ──  Load Phi-3-mini with 4-bit quantization
"""
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

MODEL_NAME = "microsoft/Phi-3-mini-4k-instruct"

bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_compute_dtype=torch.float16,
    bnb_4bit_use_double_quant=True,
    bnb_4bit_quant_type="nf4",
)

print("Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, trust_remote_code=True)
tokenizer.pad_token = tokenizer.eos_token
tokenizer.padding_side = "right"

print("Loading model (4-bit quantized)...")
model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    quantization_config=bnb_config,
    device_map="auto",
    trust_remote_code=True,
    attn_implementation="eager",  # Phi-3 requires this on T4
)

print("Model loaded. GPU memory used:", round(torch.cuda.memory_allocated() / 1e9, 2), "GB")
"""

# ── CELL 6 ──  Apply LoRA adapters
"""
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training

model = prepare_model_for_kbit_training(model)

lora_config = LoraConfig(
    r=16,
    lora_alpha=32,
    target_modules=["q_proj", "v_proj", "k_proj", "o_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM",
)

model = get_peft_model(model, lora_config)
model.print_trainable_parameters()
# Expected: ~1-2% of total parameters are trainable (the LoRA adapters only)
"""

# ── CELL 7 ──  Train  (~35-50 minutes on T4)
"""
from trl import SFTTrainer, SFTConfig

HF_USERNAME = "YOUR_HF_USERNAME"   # <-- replace with your HF username
OUTPUT_REPO = f"{HF_USERNAME}/nexus-shield-classifier"

training_args = SFTConfig(
    output_dir="./nexus-shield-adapter",
    num_train_epochs=3,
    per_device_train_batch_size=2,
    gradient_accumulation_steps=4,
    learning_rate=2e-4,
    fp16=True,
    logging_steps=20,
    save_strategy="epoch",
    eval_strategy="epoch",
    load_best_model_at_end=True,
    warmup_ratio=0.03,
    lr_scheduler_type="cosine",
    max_seq_length=512,
    dataset_text_field="text",
    report_to="none",
)

trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=dataset["train"],
    eval_dataset=dataset["test"],
    args=training_args,
)

print("Starting training...")
trainer.train()
print("Training complete.")
"""

# ── CELL 8 ──  Quick local test before pushing
"""
from transformers import pipeline

test_log = (
    "Auth failure: sshd[32258]: Failed password for invalid user admin "
    "from 192.168.97.128 port 443 ssh2. Continuous retry count=22."
)

pipe = pipeline(
    "text-generation",
    model=model,
    tokenizer=tokenizer,
    max_new_tokens=100,
    temperature=0.05,
    do_sample=True,
)

prompt = (
    f"<|system|>\n{SYSTEM_PROMPT}<|end|>\n"
    f"<|user|>\n{test_log}<|end|>\n"
    f"<|assistant|>\n"
)

result = pipe(prompt, return_full_text=False)[0]["generated_text"]
print("Model output:")
print(result)
# Expected: {"incident_report": {"vector_class": "BRUTE_FORCE_ATTEMPT", ...}}
"""

# ── CELL 9 ──  Push to Hugging Face Hub
"""
import json

# Save model + tokenizer to HF Hub
print(f"Pushing to: {OUTPUT_REPO}")
model.push_to_hub(OUTPUT_REPO, token=HF_TOKEN)
tokenizer.push_to_hub(OUTPUT_REPO, token=HF_TOKEN)

# Save the system prompt alongside the model so inference code can use it
with open("system_prompt.txt", "w") as f:
    f.write(SYSTEM_PROMPT)

from huggingface_hub import HfApi
api = HfApi()
api.upload_file(
    path_or_fileobj="system_prompt.txt",
    path_in_repo="system_prompt.txt",
    repo_id=OUTPUT_REPO,
    token=HF_TOKEN,
)

print(f"\nDone! Your model is live at:")
print(f"  https://huggingface.co/{OUTPUT_REPO}")
print(f"\nCopy this as VITE_HF_MODEL_ID in your .env.local:")
print(f"  {OUTPUT_REPO}")
"""

# ── CELL 10 ──  After pushing: copy these two values into your .env.local
"""
# VITE_HF_API_TOKEN = hf_YOUR_TOKEN_HERE
# VITE_HF_MODEL_ID  = YOUR_HF_USERNAME/nexus-shield-classifier
#
# Also add them to Vercel:
#   vercel.com → your project → Settings → Environment Variables
"""

# !pip install transformers[torch] datasets optimum onnxruntime-gpu
import shutil
from google.colab import files
from datasets import load_dataset
from transformers import AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer

# 1. Define Labels & Encoding
labels_list = ["SQLI", "XSS", "RCE", "B_OVERFLOW", "DOS", "SSRF", "PATH_TRAVERSAL", 
               "PRIV_ESC", "AUTH_FAILURE", "INFO_DISCLOSURE", "CSRF", "CMD_INJECTION", "OTHER"]
label2id = {label: i for i, label in enumerate(labels_list)}
id2label = {i: label for i, label in enumerate(labels_list)}

# 2. Load and Encode
def map_labels(example):
    example["label"] = label2id[example["label"]]
    return example

dataset = load_dataset('csv', data_files='nvd_master_2026.csv')['train']
dataset = dataset.map(map_labels) # FIX: Word -> Number
dataset = dataset.train_test_split(test_size=0.1)

# 3. Tokenize
model_id = "answerdotai/ModernBERT-base" 
tokenizer = AutoTokenizer.from_pretrained(model_id)
def tokenize_fn(batch):
    return tokenizer(batch["text"], padding="max_length", truncation=True, max_length=1024)

tokenized_data = dataset.map(tokenize_fn, batched=True)

# 4. Train
model = AutoModelForSequenceClassification.from_pretrained(
    model_id, num_labels=13, id2label=id2label, label2id=label2id
)

args = TrainingArguments(output_dir="./v_master", per_device_train_batch_size=8, num_train_epochs=3, fp16=True)
Trainer(model=model, args=args, train_dataset=tokenized_data["train"], eval_dataset=tokenized_data["test"]).train()

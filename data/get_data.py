from datasets import load_dataset
ds = load_dataset("ProtectSkills/MaliciousSkillBench", "primary", split="train")
print(len(ds))
print(ds[0].keys())
ds.to_pandas().to_csv("skills.csv", index=False)
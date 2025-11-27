# GitHub Setup Guide

## 📦 Push This Repository to GitHub

### Step 1: Create a Private Repository on GitHub

1. Go to [github.com](https://github.com) and log in
2. Click the **"+"** icon in the top right → **"New repository"**
3. Fill in the details:
   - **Repository name:** `security-ai-startup` (or any name you prefer)
   - **Description:** "Rust-based AI security tool for log analysis"
   - **Visibility:** ✅ **Private** (keep it private)
   - ❌ **Do NOT** initialize with README, .gitignore, or license (we already have these)
4. Click **"Create repository"**

### Step 2: Connect Your Local Repo to GitHub

After creating the repo, GitHub will show you commands. Use these:

```bash
# Add GitHub as the remote origin
git remote add origin https://github.com/YOUR_USERNAME/security-ai-startup.git

# Rename branch to main (optional, modern convention)
git branch -M main

# Push your code to GitHub
git push -u origin main
```

**Replace `YOUR_USERNAME`** with your actual GitHub username!

### Step 3: Verify It Worked

1. Refresh your GitHub repository page
2. You should see all your files:
   - Ideas/
   - log_parser/
   - rust-learning-roadmap.md
   - README.md

---

## 🔄 Daily Workflow: Making Changes

### After you make changes to your code:

```bash
# See what changed
git status

# Add all changes
git add .

# Commit with a descriptive message
git commit -m "Add feature X" 

# Push to GitHub
git push
```

### Example workflow:
```bash
# You modify log_parser/src/main.rs
cd /Users/senaraufi/Desktop/Startup

git status                           # See what changed
git add log_parser/src/main.rs       # Stage the file
git commit -m "Add IP counting feature to log parser"
git push                             # Send to GitHub
```

---

## 🌍 Working From Another Computer

### First time on a new computer:

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/security-ai-startup.git

# Navigate into it
cd security-ai-startup

# Start working!
cd log_parser
cargo run
```

### Pulling latest changes:

```bash
# Get the latest code from GitHub
git pull

# Now you have the latest version
```

---

## 📝 Useful Git Commands

```bash
# See commit history
git log --oneline

# See what changed in files
git diff

# Undo changes to a file (before commit)
git restore filename

# See all branches
git branch

# Create a new branch for experiments
git checkout -b feature-name

# Switch back to main branch
git checkout main
```

---

## 🔐 Authentication Options

### Option 1: HTTPS with Personal Access Token (Recommended)

1. Go to GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Generate new token with `repo` scope
3. Use token as password when pushing

### Option 2: SSH Keys (More Convenient)

1. Generate SSH key:
   ```bash
   ssh-keygen -t ed25519 -C "your_email@example.com"
   ```
2. Add to GitHub: Settings → SSH and GPG keys → New SSH key
3. Use SSH URL instead:
   ```bash
   git remote set-url origin git@github.com:YOUR_USERNAME/security-ai-startup.git
   ```

---

## 🎯 Best Practices

### Commit Messages
- ✅ Good: "Add failed login detection to log parser"
- ✅ Good: "Fix regex pattern for IP extraction"
- ❌ Bad: "update"
- ❌ Bad: "changes"

### When to Commit
- After completing a feature
- After fixing a bug
- Before switching tasks
- At the end of each work session

### What NOT to Commit
- ❌ API keys or secrets
- ❌ `target/` directory (Rust build artifacts)
- ❌ `.env` files with credentials
- ❌ Real security logs with sensitive data
- ✅ These are already in `.gitignore`

---

## 🚨 If You Make a Mistake

### Committed sensitive data?
```bash
# Remove file from git but keep locally
git rm --cached sensitive_file.txt
git commit -m "Remove sensitive file"
git push

# Then add to .gitignore
echo "sensitive_file.txt" >> .gitignore
```

### Want to undo last commit?
```bash
# Undo commit but keep changes
git reset --soft HEAD~1

# Undo commit and discard changes (careful!)
git reset --hard HEAD~1
```

---

## 📊 Your Repository is Now:

✅ Properly initialized with git  
✅ Has a clean structure  
✅ Includes .gitignore for Rust projects  
✅ Has comprehensive documentation  
✅ Ready to push to GitHub  
✅ Can be accessed from anywhere  

**Next step:** Follow Step 1-3 above to push to GitHub! 🚀

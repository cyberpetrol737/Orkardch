# Putting Orkardch on GitHub (beginner steps)

You have **Orkardch.zip**. It contains **only files, no folders**, so after you unzip, the folder you
open already looks like the repository.

## Option A: GitHub website (no commands)

1. Sign in at github.com. Tap **+** → **New repository**.
2. Give it a name (for example `orkardch`). Leave "Add a README" **unticked** so the repository is empty.
   Choose Public or Private. Tap **Create repository**.
3. Extract **Orkardch.zip** into a new folder. There are no sub-folders: every file lands side by side.
4. On the new repository page tap **uploading an existing file**, select **all the files** from that
   folder, and drop or pick them. (Some phone file pickers hide files that start with a dot, such as
   `.gitignore`. It is optional: if yours is hidden, upload the rest and carry on.)
5. Scroll down and tap **Commit changes**.
6. **Check:** the repository page should list `README.md`, `package.json`, `orkardch.js` and the other
   files directly, with no folder to open first.

## Option B: Git commands (Termux or a computer)

```sh
unzip Orkardch.zip -d orkardch-files
cd orkardch-files    # all the files are right here, side by side
git init
git add .
git commit -m "Add Orkardch"
git branch -M main
git remote add origin <YOUR-REPOSITORY-URL>      # copy it from your new empty repository page
git push -u origin main
```

Replace `<YOUR-REPOSITORY-URL>` with the address GitHub shows on your repository page
(`https://github.com/<you>/<repo>.git`). GitHub will ask you to sign in; use a personal access token
as the password if it asks for one. Orkardch never includes or asks for any credentials.

## Use it from the repository

```sh
git clone <YOUR-REPOSITORY-URL> ~/orkardch
cd ~/orkardch
sh install-termux.sh
orkardch
```

## Notes

* No license is included. Add a `LICENSE` file (GitHub offers templates) before making it public.
* `.gitignore` already keeps local settings, investigations, caches, logs, `node_modules` and ZIP files
  out of the repository.
* You never need to edit any file for it to work after upload.

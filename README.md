# BlackHat-Arsenal
Covers the Arsenal of the BlackHat-Events in ASIA/EU/USA/MEA

# Info

Last year I've created a repository of the Arsenal which where presented at the BlackHat EU 2021. In this repository I'll gonna continue it for the BlackHat Asia/US/EU. 
Here is already a good list https://github.com/toolswatch/blackhat-arsenal-tools but I do it mostly for myself to check weather a tool might be useful for me or not and I like to share it with you. If you find any missing links/repositories or any useful information don't hesitate to contact me. Thanks

# Crawler

Quickly written crawler to fetch description and summaries.

Updated using playwright and selenium as fallback
```
# in your venv
python -m pip install -r requirements.txt

# then install Playwright browser binaries
python -m playwright install chromium
```

Otherwise chromedriver must be in the path to work

# Categories

Since https://github.com/toolswatch/blackhat-arsenal-tools is archive, I'll gonna continue their work as good as possible.

**_NOTE:_**
If you speaker/creator and would like to add some more information, I gladly merge a pull request. You can take the simplified tool_name.md from this repo or from the [original one](https://github.com/toolswatch/blackhat-arsenal-tools/blob/master/tool_name.md)


Scriptinfo to categorize
```
# in your venv
python -m pip install -r merge-arsenal-requirements.txt
python -m playwright install

# from the root of your BlackHat-Arsenal repo
python merge_arsenal_md_with_categories.py --root . --outdir Categories

# dry-run to preview planned writes
python merge_arsenal_md_with_categories.py --root . --outdir Categories --dry-run
```
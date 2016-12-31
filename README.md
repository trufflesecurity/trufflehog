# Truffle Hog
Searches through git repositories for high entropy strings, digging deep into commit history and branches. This is effective at finding secrets accidentally committed that contain high entropy.

![Example](https://i.imgur.com/aGSIEd9.png)

## Setup
The only requirement is GitPython, which can be installed with the following
```
pip install -r requirements.txt
```

## How it works
This module will go through the entire commit history of each branch, and check each diff from each commit, and evaluate the shannon entropy for both the base64 char set and hexidecimal char set for every blob of text in each diff. If at any point a high entropy string is detected, it will print to the screen. 

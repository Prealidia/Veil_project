import subprocess
import sys
import os

def titolo():
  try:
    subprocess.run(["figlet", "-f", "slant", "pkgs-manager"])
  except FileNotFoundError:
    print("P K G S - M A N A G E R ")

def description():
  print("\ndefault first pkgs to upgrade = xbps")

def update():
  upgradeXbps=subprocess.run(["sudo", "xbps-install", "-Su"])
  upgradeNix=subprocess.run(["nix-channel", "--update"])
  if upgradeXbps.returncode != 0:
    print("Couldn't upgrade xbps!")
  else:
    try:
      oldPkgs=input("\n Wanna delete old pkgs and orfan dependency? [y,N]: ")
    except(KeyboardInterrupt, EOFError):
      print("\nBye!")
      sys.exit(0)
    if oldPkgs.lower() == "y":
      subprocess.run(["sudo xbps-remove -o"], shell=True)
    elif oldPkgs.lower() == "q":
      print("\nBye!")
      sys.exit(0)
  if upgradeNix.returncode != 0:
    print("Couldn't upgrade nixpkgs!")

  return

def install():
  print("pkgs to install?")
  try:
    pkgs=input("> ")
  except(KeyboardInterrupt, EOFError):
    print("\nBye!")
    sys.exit(0)
  if pkgs == "q":
    print("\nBye!")
    sys.exit(0)
  else:
    installXbps=subprocess.run(["sudo", "xbps-install", "-S", pkgs])
    if installXbps.returncode != 0:
      print(f"Couldn't install {pkgs}!")
      print("")
      nix=input("Install it with nixpkgs? [y,N]: ")
      if nix.lower() == "y":
        searchNix=subprocess.run(["nix", "search", "nixpkgs", pkgs], stdout=subprocess.DEVNULL)
        if searchNix.returncode != 0:
          print("Couldn't not find the pkgs!")
          return
        else:
          installNix=subprocess.run([f"nix profile add nixpkgs#{pkgs}"], shell=True)
          if installNix.returncode != 0:
            print(f"Couldn't not install {pkgs} even with nixpkgs!")
      else:
        return

def remove():
  print("pkgs to remove?")
  try:
    pkgs=input("> ")
  except(KeyboardInterrupt, EOFError):
    print("\nBye!")
    sys.exit(0)
  if pkgs == "q":
    print("\nBye!")
    sys.exit(0)
  else:       
    removeXbps=subprocess.run(["sudo", "xbps-remove", pkgs])
    if removeXbps.returncode != 0:
      removeNix=subprocess.run(["nix", "profile", "remove", pkgs], stderr=subprocess.DEVNULL)
      if removeNix.returncode != 0:
        print(f"pkgs {pkgs} not found!")
      else:
        print(f"nixpkgs {pkgs} removed")
    else:
      print(f"xbps {pkgs} removed")
   
def manager():
  while True:
    os.system("clear")
    titolo()
    description()
    print("Choose:")
    print("1.upgrade")
    print("2.install")
    print("3.remove")
    try:
      scegliere=input("\n> ")
    except(KeyboardInterrupt, EOFError):
      print("\nBye!")
      sys.exit(0)
    if scegliere == "1" or scegliere.lower() == "upgrade":
      update()
    elif scegliere == "2" or scegliere.lower() == "install":
      install()
    elif scegliere == "3" or scegliere.lower() == "remove":
      remove()
    elif scegliere == "q" or scegliere.lower() == "exit":
      print("\nBye!")
      sys.exit(0)  
    input("\nPremi invio per continuare...")

manager()

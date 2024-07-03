1.      Download the cert installer file here: 
https://zuryc.sharefile.com/public/share/web-s8ff289dd7437438db02941859e633782  
2.      Save the file to an easily accessible folder.  We recommend c:\dhg 
3.      Open an elevated PowerShell prompt and change directory to the script location.  
4.      Type in Set-ExecutionPolicy Unrestricted and press enter.  Type ‘A’ for Yes to All and hit enter 
  
5.      “Type in: .\DHGClientCertSetup.ps1 (This will download the initial files and install the CA) 
At the security warning, Choose R for ‘Run Once’ and hit enter 
  
Type ‘Y’ and hit enter to download the latest Citrix Workspace.  If already installed, click N 
Type ‘Y’ and hit enter to generate an account/certificate for the device  
answer the remaining questions based on your app needs. 
 
6.      To provide the MFA code, you must scan the QR code with your favorite MFA App.  
On your smartphone, download and install an authenticator app from the app store 
Click the Add button on your authenticator app and point your phone camera to the QR code below: 
  
The app will add an account called “DHG-Client-Installer” and will display a 6-digit code that changes every thirty seconds.  After entering the code, you will have the choice to install Citrix Workspace from the download or type N if you already have a version installed. 
7.      Once completed you will have an DHG Apps icon on the users desktop. Double click the icon and you will be taken to https://remoteapps.dhtsg.net. Here are the Apps you chose during the setup. Launch each app to test  
You may be prompted to agree to accept the certificate for each browser that you use to access the site. 
 

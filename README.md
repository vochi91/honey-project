# honey-project
# Building a SOC + Honeynet in Azure (Live Traffic)
![image](https://github.com/user-attachments/assets/1974b4f8-7332-4ebd-99c1-59d70491a0b4)


In this project, I created a small honeynet in Microsoft Azure — a test environment designed to attract and monitor attacks. I connected different log sources (like virtual machines and active directory data) to my Log Analytics workspace. This workspace sends data to Microsoft Sentinel, where I built visual attack maps, set up alerts, and tracked security incidents.

I first ran the environment without any protection for 24 hours to collect security data. Then, I added security controls to make the environment safer and ran it for another 24 hours. Below, I’ll show the results and compare how things changed after applying those security improvements.

The security metrics we’ll look at include:

- SecurityEvent – Windows event logs that record security-related activities on Windows virtual machines, such as logins or failed login attempts.
- Syslog – These are security logs from Linux virtual machines that help track user activity, errors, and other important system events.
- SecurityAlert – These are alerts automatically triggered by Microsoft Sentinel when suspicious or potentially harmful activity is detected based on incoming data.
- SecurityIncident – These are collections of related alerts grouped together by Sentinel that will help us investigate and respond to threats more easily.
- AzureNetworkAnalytics_CL – This log tracks network traffic, especially showing which potentially malicious connections were allowed into our honeynet (the test environment set up to draw in attackers).

## Architecture Before Hardening / Security Controls
![Architecture Diagram](https://i.imgur.com/aBDwnKb.jpg)

## Architecture After Hardening / Security Controls
![Architecture Diagram](https://i.imgur.com/YQNa9Pp.jpg)

The tools needed for our minihoneynet project will consist of:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (1st windows, 2nd attack windows, 1 linux)
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel
- Microsoft Defender for Cloud
- SQL Server

##
<details><summary>🔽Resource Group</summary>

The first thing we are going to do is create a resource group so that we have a folder that keeps all the related cloud stuff for a project—like virtual machines, storage, and settings—organized in one place.
1) Create a name for the resource group. We will call ours  "Honey-Files"
2) Choose a region where we will deploy our VMS, create our log analytic workspace, NSGS etc

![image](https://github.com/user-attachments/assets/3e0e8f6e-6217-410f-a1bf-03a6808f5e1d)

![image](https://github.com/user-attachments/assets/d289e4e5-af69-4022-b8ad-4a7c381e9715)

</details>

##
<details><summary>🔽Windows Virtual Machine</summary>

Create Windows 10 Pro Virtual Machine
![image](https://github.com/user-attachments/assets/dbcbfc22-8670-4d1d-9941-d19e8a36cb32)


1.Use the same resource group created
2. Name the VM: (windows-vm)
3. Region: EAST US 2
4. Resource Group: RG-Cyber-Lab
5. Virtual Network: Lab-VNet

When done review and create.
![image](https://github.com/user-attachments/assets/988f455b-3bc1-4786-87be-2dffd995af97)
![image](https://github.com/user-attachments/assets/5afbdc77-6199-46af-8591-7124d78d4382)
![image](https://github.com/user-attachments/assets/149f3c6e-1572-4e80-bd05-631fe4fc1aa7)



</details>


##
<details><summary>🔽 Linux Virtual Machine</summary>

Create  Ubuntu (Linux) Virtual Machine
1. Name the VM: (linux-vm).
2. Same Region, Resource Group, and VNet as windows-vm
3. We will use a username and password instead for authentication
   
![image](https://github.com/user-attachments/assets/1f00074f-ba53-4036-85b8-854cb5cee22b)
![image](https://github.com/user-attachments/assets/0513b906-e447-4918-91cd-9e26e842afe9)
![image](https://github.com/user-attachments/assets/a61c97e3-7aa2-4cf3-824f-a95f85024325)
![image](https://github.com/user-attachments/assets/875b1bf6-613f-4c1c-a9ea-17951ced3a24)


We will deliberately open up the ports to the internet, to create a vulnerable environment so that we can attract attention from the red team.
</details>


##
<details><summary>🔽 Windows Attack Virtual Machine</summary>

  Create another Windows VM in a region and zone outside the US and NAME IT “attack-vm”
1. Name: attack-vm
2. Resource Group: RED-FILES
3. Region: Asia Pacific- East Asia
   ![image](https://github.com/user-attachments/assets/744c5d54-60da-46d5-b510-f7b61626678d)
   ![image](https://github.com/user-attachments/assets/a421f58c-790a-4e3f-a572-3b2f13168a63)
![image](https://github.com/user-attachments/assets/762b12b8-0983-4b61-86a9-95a7b7bc2259)

   

</details>


##
<details><summary>🔽 Network Security Group </summary>

- Our Network Security Group is the firewall or security gate of our virtual network. 
- It decides who is allowed in or ho gets bloackd when trying to conect to our virtual machine.
- We will open up the gates all the way, so anyone can cnnect out VMs.

  Inbound Rules
  - Inbound is all the traffic coming into our vms.
  - Inbond Rules will allow or block that traffic. If we dont allow traffic then our VMS will just sit there without keeping track of any activity or alerts to log.
 
    Step by Step Breakdown
    1) We will go to our windows vm and locate the network settings
       ![image](https://github.com/user-attachments/assets/d4cf4581-1f5b-452b-99da-d7fa693e65d2)

    2) Create a new inbound rule
       ![image](https://github.com/user-attachments/assets/c0beab45-bb75-4487-bddf-fd1e663e84b3)

      -  We will change the desintation port range from 8080 to * allowing inbound traffic from any port.
      -  We will change the priority to 100 which is the minimum. The lower the number the higher the priority will be compared to ther inbound rule that are already present.
      -  we will name the rule "DangerAllowAnyCustomAnyInbound"
      -  Keep everything else at default and press Add.
      ![image](https://github.com/user-attachments/assets/d57aaf78-271a-4ea9-9917-15f9b3e3ee45)


Repeat the same exact process for Linux vm.


 

   
</details>


##
<details><summary>🔽Windows Firewall</summary>

We are now going to RDP into our windows vm to turn off the firewall. This will make the environment even more insecure because our firewall blocks unauthorized network access.

Step 1: We will search Windows Remote Dextop Connection (RDP) and then log in with our IP address and the VM's login credentials
![image](https://github.com/user-attachments/assets/9ae336a0-1387-4333-9bd0-7e0a1656dbda)
![image](https://github.com/user-attachments/assets/82c3b4c2-5dfc-4fae-829a-48276c0556ce)
![image](https://github.com/user-attachments/assets/0505228d-3cd3-407b-81d2-ffffb65d74e4)

Step 2: search for Windows Firewall or "wf.msc" 
![image](https://github.com/user-attachments/assets/d885d045-5492-4737-8678-0e3aa64a9acc)

Step 3: Disable Firewall 
![image](https://github.com/user-attachments/assets/cc0597a6-3335-41f4-b049-b259aadfe4d5)
![image](https://github.com/user-attachments/assets/4fd53b16-4d8f-49aa-b28d-6a54cc85107a)
![image](https://github.com/user-attachments/assets/68de6e1d-669c-4900-b737-b7a25c5d603a)
![image](https://github.com/user-attachments/assets/b2003179-597d-407d-aec6-c9ce0aee9577)
![image](https://github.com/user-attachments/assets/b1f88017-a2ca-4e84-97ef-1d2df3c7f6a1)

Step 4: Test Firewall vulnerability by using my windows vm to ping my linux vm.
Open command line on windows, type ping and then the ip address of linux.
![image](https://github.com/user-attachments/assets/4e555d51-4245-4745-8aa7-09b0a42981aa)

Firewall is down now so other devices will be able to have access.


</details>


##
<details><summary>🔽SQL Server Config</summary>

- SQL Server is a database that stores information such as passwords, logs etc.
- Since they hold sensitive information, they are easy targets for hackers.
- We are going to install SQL server so that we can have instrument to generate logs.


  Step 1: In the windows vm, install SQL server eval: https://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2019
  ![image](https://github.com/user-attachments/assets/9f5c368a-de7b-4fda-8215-eeda19b92411)
  ![image](https://github.com/user-attachments/assets/d55aa113-f2fa-42df-90a8-8aa07763857a)
  ![image](https://github.com/user-attachments/assets/b1125d59-ba17-45ba-b13b-a251456559fd)
  ![image](https://github.com/user-attachments/assets/36fe98b6-f61d-497e-83d4-854937085044)
  ![image](https://github.com/user-attachments/assets/70d93635-b6f5-42c9-9c22-ac241a98fac0)
  ![image](https://github.com/user-attachments/assets/43f11f46-f98e-4d2a-a007-96844331a6b8)
  ![image](https://github.com/user-attachments/assets/d160fcba-8cb0-427d-bb3d-e86fb8900d7a)
  ![image](https://github.com/user-attachments/assets/4c9d6efe-75cf-4d0d-8c85-8dcf51e58aed)
  ![image](https://github.com/user-attachments/assets/0f8d6d21-9dc5-42e6-8840-5a56c12bced0)
  ![image](https://github.com/user-attachments/assets/bb450b9c-3a39-4731-b4ec-44424f8d3cec)
  ![image](https://github.com/user-attachments/assets/871b8027-2e9d-4a7c-a129-49e4cdfea9d8)
  ![image](https://github.com/user-attachments/assets/ab1cfb28-1d4d-43d6-a7be-51c4452a3028)
  ![image](https://github.com/user-attachments/assets/efd1d273-1f23-463f-8259-2ac21e4cac74)
  ![image](https://github.com/user-attachments/assets/1bb77c0d-3e79-4233-93e9-552a35382d1f)
  ![image](https://github.com/user-attachments/assets/e77bcd6a-c8b6-4410-b78e-ed8ceb027d4a)
  ![image](https://github.com/user-attachments/assets/8a214e1b-a365-4945-8451-59e829eb8a89)


Step 2; Download SQL Server Management Studio (connecting app to our SQL database): https://sqlserverbuilds.blogspot.com/2018/01/sql-server-management-studio-ssms.html#google_vignette

![image](https://github.com/user-attachments/assets/10618625-200a-43e5-9f2b-6e7a905c00b8)
![image](https://github.com/user-attachments/assets/9203fb91-22a4-44b8-95d7-7e960c967702)
![image](https://github.com/user-attachments/assets/4ac66ef9-86d9-4fc6-84a9-dcfbeb948a4a)

Step 3: We will enable logging for our SQL

   1) Go to Registry Editor on windows search
   ![image](https://github.com/user-attachments/assets/778d0d1d-2fd6-431a-a715-00867f5ad625)

   2) In this order: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security
   ![image](https://github.com/user-attachments/assets/f9f6f9cc-e685-4cb7-a0ac-66d8047c2975)
   ![image](https://github.com/user-attachments/assets/537aa0bb-1bbd-41a9-90f2-300032198293)

   3) Right click Security key, go to permission
   ![image](https://github.com/user-attachments/assets/f85f0c14-bdce-409d-9a30-369fe97aff15)
   ![image](https://github.com/user-attachments/assets/8a7d0902-d126-41c6-9f74-e780371f91ef)
   ![image](https://github.com/user-attachments/assets/b963fc1b-1fa2-4f29-a0ac-6c40c7fb2c69)

Step 4: Configure audit object access setting in Windows VM (use a command line to turn on windows logging to view suspicious activity)

   1) Open Command Line as an admin
      ![image](https://github.com/user-attachments/assets/91cf1344-b3f3-4bc8-8743-df2cff447daf)
  
   2) Type this command "auditpol /set /subcategory:"application generated" /success:enable /failure:enable"
      ![image](https://github.com/user-attachments/assets/ef4eb241-ad92-4d29-964a-27e8b72aa91c)

Step 5: Enable auditing on the connector app for our SQL Server (SQL SERVER MANAGEMENT STUDIO or SSMS)

   1) Open SSMS
      ![image](https://github.com/user-attachments/assets/c3758305-cb7f-4ca8-9c74-91d628b4e694)

   2) Login with credentials from SQL Server setup and connect
       ![image](https://github.com/user-attachments/assets/ef618dd0-dd8d-4819-9c40-5b69a8241cb8)
   
   3) Rightclick and go to properties
      ![image](https://github.com/user-attachments/assets/15f77618-6f59-4fcd-ace5-5cbc3cba1eae)

   4) When you enter "Security" change settings to "both failed and succesful logins"
      ![image](https://github.com/user-attachments/assets/0d16045f-f780-4de9-8f62-c8640799e4f4)

   5) Restart settings to solidify changes.
      ![image](https://github.com/user-attachments/assets/77e7f33f-1c08-4938-bc1a-d378dedac4ba)


</details>


##
<details><summary>🔽Log Analytics Workspace</summary>

We will be creating our Log Analytic Workspace or "LAW" (soc-surveillance). This is the nucleus of our honeynet project. It is like a giant cloud notebook that collects and organzies data so that we can detect and investigate suspiscious activity. This will be the location of all of our activities in active directory, virtual network, network security groups, and our SIEM (Sentinel) 

Step 1: search Log Analytic Workspace 
   ![image](https://github.com/user-attachments/assets/8da7b451-be34-4d2d-9c03-20d6da3d0490)

Step 2: Create 
   1) We are using our same resource group "Honey-Files"
   2) We will call our LAW "soc-surveillance"
   3) Same region as Resource group and Virtual machines
   4) Review and Create
   
   ![image](https://github.com/user-attachments/assets/8f5e4aed-894b-4b0b-ae6d-bc928be8ec5e)
   ![image](https://github.com/user-attachments/assets/79a8969e-54b9-4f70-819e-268f6362c625)
   ![image](https://github.com/user-attachments/assets/67369938-f8a3-4462-a527-9c0ed3ef4a46)



</details>








##
<details><summary>🔽Microsoft Sentinel</summary>



Microsoft Sentinel is our security control room, just like security cameras in a building, it watches every activity that is happening in our system. Through this SIEM we will turn our LAW into a security investigation platform by connecting the two.

Step 1: Create Sentinel
   ![image](https://github.com/user-attachments/assets/0b84e01e-9ffa-45c4-a775-a6c045800477)
   ![image](https://github.com/user-attachments/assets/856bb8de-ed26-465b-916d-25685ad70b4d)

Step 2: Connect to LAW

   ![image](https://github.com/user-attachments/assets/313cd8bb-6d7d-4168-8ac4-0fe3149e7365)

Step 3: Create a watchlist in Sentinel
- We will upload IP-related geodata as a reference point for Sentinel in the future to intelligently track more suspicious activity.
- This will help narrow down our search to a certain rgion, city if possible.

   1) Go to Sentinel and locate watchlist, then create new.
     ![image](https://github.com/user-attachments/assets/ca264a15-f3c8-41a6-a15e-e4faf4ab9bbb)
     ![image](https://github.com/user-attachments/assets/f9a2c862-6f79-4852-8bc1-8c844777680f)

   2) Upload and name geodata file.
      - Keep name and alias the same.
        ![image](https://github.com/user-attachments/assets/e3d75cec-b45e-485c-844d-432e81f4bc30)
        - Upload the gile. Keep everything else default. The only thing you ltar is changing searchkey to network
          ![image](https://github.com/user-attachments/assets/c2b98955-39dc-440e-adb8-c378cf435867)
          ![image](https://github.com/user-attachments/assets/8977f07a-b746-4717-9632-b9561889da63)

   3) Go to Log Analytics Workspace and check that Sentinel has received and loaded our geo-data correctly
      - Go to LAW and then locate the log section
        ![image](https://github.com/user-attachments/assets/ef54adb6-ab5d-467e-9d8e-595702333dcd)
      - Make sure KQL mode is on an type in _GetWatchlist("geoip"). If it worked, we’ll see a table appear with columns like country, IP ranges, etc
        ![image](https://github.com/user-attachments/assets/28a80b80-eec5-4a4e-82f2-8d0323589cb6)
      -Ensure the download is completed for the watchlist.
         ![image](https://github.com/user-attachments/assets/ddaa72f1-0f5d-4892-b3d4-a911876fcc7f)




   


</details>




##
<details><summary>🔽Microsoft Defender for Cloud</summary>

Defender for Cloud is the security guard, the line of defense for our cloud infrastructure and all the resources(virtual machine, databases, files etc) in it.
 - Cloud scans for intruders
 - Cloud alerts if enemies are nearby
 - Cloud tells you what walls to harden and reinforce.

We will take logs from our security groups and vms, injesting them into our LAW.

Step 1: Enable Microsoft Defender for Cloud for Log Analytics Workspace
- Open up MDC on Azure and then go to environment settings.
   ![image](https://github.com/user-attachments/assets/798cebac-029d-47a2-b28f-12267664fdcc)
  ![image](https://github.com/user-attachments/assets/0eadd47b-ec95-4891-9fcf-98b96c6d5edc)
- Scroll down and expand the subscription until we see our LAW, and then edit settings.
  ![image](https://github.com/user-attachments/assets/b5e6a7c7-b9f4-4a64-ac5e-b0ba9ab77084)
- Go to defender plans to turn on servers, and sql servers to allow us to collect logs from vms and SQL server.
  ![image](https://github.com/user-attachments/assets/cfefaf31-b224-4cbb-acb8-66154fdb05bd)
- Go to data collection and cehck "All Events" so we can collect all events from Windows Security Log
  ![image](https://github.com/user-attachments/assets/10370b2e-6a57-425f-a702-df773b6ca0d7)

  Step 2: Enable Microsoft Defender for Cloud for Azure Subcription, this ensures MDC is protecting our entire cloud environment — not just the VMs.
  - Go back to Environment settings, go to Subscription this time and edit settings.
    ![image](https://github.com/user-attachments/assets/3f0ecc6d-fb3f-4739-a575-ce0b7f633eec)
  - Under Defender Plans, turn on protection for Servers, Key Vault, Storage, and Databse
    ![image](https://github.com/user-attachments/assets/5be3fa62-844c-468d-aaaf-7c4ae13fc76d)

Step 3: Enable Microsoft Defender for Cloud Continuous Export in Environment Settings: this will export alerts to LAW for future KQL queries
- Under Continous Export, go to Log Analytics Workspace and permit all data to be exportd to LAW
  ![image](https://github.com/user-attachments/assets/a96f178a-8689-45cf-b884-ebca78a99b26)
  Scroll down and export config to our resource group "Honey-Files", and finally export to our our LAW and save everything.
     ![image](https://github.com/user-attachments/assets/6cbd40db-6ccd-41f5-99fe-1969f68fc0e5)

MDC is eabled.






</details>



##
<details><summary>🔽Logging and Monitoring</summary>

In this section we will be configure logging for all of our virtual machines (excluding attack vm) network security groups. It will be a different process for our virtual networks compared to other resources in Azure because our vms require agents to be installed and configured to enable logging.

Step 1: Create a storage account to store our NSG flow logs in.
   - ![image](https://github.com/user-attachments/assets/bf14c742-1c8f-4bb8-bd18-a265047559c7)
   - We will name it "securityvault", using the same resource group and region that we have been using. Once done we review and create.
     ![image](https://github.com/user-attachments/assets/afd47338-2b1d-43bf-8f88-c6f1de0f26e4)

Step 2: Enable flow logs for NSG.
   - ![image](https://github.com/user-attachments/assets/1fc890a0-bc00-4097-a70c-8c65bca31de5)
   - Go to anyone of our vm's network security group (there should be one for each vm) and click nsg flow log.
     ![image](https://github.com/user-attachments/assets/61384461-b6e5-400d-9194-f24ec29fa585)
     ![image](https://github.com/user-attachments/assets/53985fc1-902b-4762-91db-8f7e7837fd43)
     - Create a new flow log
       ![image](https://github.com/user-attachments/assets/a7365fa7-aa02-4339-990d-7d56f1df15d6)
     - Target resource will be for both network security groups, use the same LAW and storage account that we just created "securityvault"
       ![image](https://github.com/user-attachments/assets/2f657c0f-203a-4286-9681-131c270c7d0a)
       ![image](https://github.com/user-attachments/assets/84835d70-997d-4ff0-b891-0e9167196100)
       ![image](https://github.com/user-attachments/assets/f11563f5-8476-4ecd-9334-29101b209c19)
      ![image](https://github.com/user-attachments/assets/f05888bf-e225-481a-936e-cca549a167dc)

Step 3: Configure Data Collection Rules for our VMs within Microsoft Sentinel

We will be setting up rules to collect important logs from your Virtual Machines (VMs) so that Microsoft Sentinel can monitor them.
Think of it like: "Hey Sentinel, here are the computers (VMs). I want you to keep an eye on these specific types of events (like login attempts or errors)."
These rules are called Data Collection Rules (DCRs).

- Go to sentinel and click on our LAW "soc-surveillance".
   ![image](https://github.com/user-attachments/assets/398f7d30-99a3-451b-bbd3-f9ec3cfdd50d)
-Scroll down to Cintent Hub under Content Management
   ![image](https://github.com/user-attachments/assets/e83ccf88-3720-450a-9b6c-5092d1dc1483)
- We will install monitoring agents for both of our virtual machines. 'Window Security Events" for windows vm and "Syslog" for linux.
  ![image](https://github.com/user-attachments/assets/22e5b4fd-be6a-455d-aefc-5129e1221917)
  ![image](https://github.com/user-attachments/assets/1c192cac-8a4d-4adf-b473-171c930a1691)
- Check under VM -> Settings -> Extensions Applications for both the Windows and Linux VM and ensure the agent is installed with “Provisioning succeeded”
  ![image](https://github.com/user-attachments/assets/382425a1-e49d-4fed-9ebd-3e4a6efc0044)
   ![image](https://github.com/user-attachments/assets/8a19bf44-5250-41e4-a66b-257dff66054c)
  ![image](https://github.com/user-attachments/assets/0bad0f0e-45bd-4738-8b53-9affca7d5dbd)
-Once installed we will then go to the installed agent to connect to our LAW.
  ![image](https://github.com/user-attachments/assets/4fbd7f70-15bd-4237-8e6d-d32369ff90da)
  ![image](https://github.com/user-attachments/assets/e6aee6a1-3207-4de0-a68c-75d977e35369)
- Create DRC for windows vm "DRC-Windows", connect to same resource group and LAW
  ![image](https://github.com/user-attachments/assets/1e343d0f-4e8d-41c6-9ebe-794580edfedc)
  ![image](https://github.com/user-attachments/assets/99f5c2cc-b19d-435e-a60b-6e3c7e06f544)
  ![image](https://github.com/user-attachments/assets/96671c89-6e79-4328-96f8-a4d7063bb61a)
  ![image](https://github.com/user-attachments/assets/222a839c-09c3-4c47-a57f-4c622fbe6ea7)
  ![image](https://github.com/user-attachments/assets/ae4eab12-ebd6-4940-9877-009f3bce7eee)
- Create DRC for linux vm "DRC-Linux", connect to same resource group and LAW
  ![image](https://github.com/user-attachments/assets/76e26034-73e6-445a-874e-052a438672e0)
  ![image](https://github.com/user-attachments/assets/e44ceb7a-b76a-43ee-b357-df1f935ee3f8)
  ![image](https://github.com/user-attachments/assets/028a0592-78de-4286-889a-e3dff9b151d2)
  ![image](https://github.com/user-attachments/assets/6ad0b336-a476-406a-9e99-8d77d36f3ed0)
  ![image](https://github.com/user-attachments/assets/9ddf3971-1797-4310-ad61-6fa299d3a211)
  ![image](https://github.com/user-attachments/assets/5931dc8c-6b41-4bdf-b780-cecc5117bd85)
  ![image](https://github.com/user-attachments/assets/c8606fc5-ef8d-475a-a133-9b54bd062342)

Step 4: Begin to query logs from LAW from our vms and NSGS. We should see logs from thse three sources:
- Syslog(linux)
- SecurityEvent(windows)
- AzureNetworkAnalytics_CL(NSG)

![image](https://github.com/user-attachments/assets/7550e8bf-70fd-4248-adad-0b3cad392d9c)
![image](https://github.com/user-attachments/assets/cee6cf62-c7de-4f80-992a-2bcdc9e0ca07)













  


   








     














## Attack Maps Before Hardening / Security Controls
![NSG Allowed Inbound Malicious Flows](https://i.imgur.com/1qvswSX.png)<br>
![Linux Syslog Auth Failures](https://i.imgur.com/G1YgZt6.png)<br>
![Windows RDP/SMB Auth Failures](https://i.imgur.com/ESr9Dlv.png)<br>

## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:
Start Time 2023-03-15 17:04:29
Stop Time 2023-03-16 17:04:29

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 19470
| Syslog                   | 3028
| SecurityAlert            | 10
| SecurityIncident         | 348
| AzureNetworkAnalytics_CL | 843

## Attack Maps Before Hardening / Security Controls

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:
Start Time 2023-03-18 15:37
Stop Time	2023-03-19 15:37

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 8778
| Syslog                   | 25
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0

## Conclusion

In this project, a mini honeynet was constructed in Microsoft Azure and log sources were integrated into a Log Analytics workspace. Microsoft Sentinel was employed to trigger alerts and create incidents based on the ingested logs. Additionally, metrics were measured in the insecure environment before security controls were applied, and then again after implementing security measures. It is noteworthy that the number of security events and incidents were drastically reduced after the security controls were applied, demonstrating their effectiveness.

It is worth noting that if the resources within the network were heavily utilized by regular users, it is likely that more security events and alerts may have been generated within the 24-hour period following the implementation of the security controls.

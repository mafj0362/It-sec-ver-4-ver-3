using System;
using System.Text.Json;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;

namespace ItSec_ver4
{
   public class Input
    {
        public void Välkommen(string []choicearr)
        {
            string secretkeyinp;
            string choice = choicearr[0].ToUpper();
            string clientFile = "";
            string serverFile = "";
            string prop = "";
            //string readFile = "";
            string masterpassword;
            Console.WriteLine("Skriv kommando");
            

            switch (choice)
            {
                
                case "INIT":
                    clientFile = choicearr[1];
                    serverFile = choicearr[2];
                    Console.WriteLine("Skriv in ditt lösenord");
                    masterpassword = Console.ReadLine();
                    Init(clientFile, serverFile, masterpassword);


                break;
                case "CREATE":
                    clientFile = choicearr[1];
                    serverFile = choicearr[2];
                    Console.WriteLine("Skriv ditt lösenord");
                    masterpassword = Console.ReadLine();
                        Console.WriteLine("Skriv secretkey");
                    secretkeyinp = Console.ReadLine();
                   
                        Create(clientFile, serverFile, masterpassword, secretkeyinp);
    
                    break;
                //case "GET":
                //    clientFile = choicearr[1];
                //    serverFile = choicearr[2];
                //    if (choicearr.Length == 3)
                //    {
                //        prop = choicearr[2];
                //    }
                //    else
                //        prop = null;
                //    Console.WriteLine("Skriv ditt lösenord");
                //    masterpassword = Console.ReadLine();
                //    GetMalte(clientFile, serverFile, prop, masterpassword);
                //    break;

                //ny get?
                case "GET":
                    clientFile = choicearr[1];
                    serverFile = choicearr[2];
                    if (choicearr.Length == 4)
                    {
                        prop = choicearr[3];
                    }
                    else
                    {
                        prop = null;
                    }
                    Console.WriteLine("Skriv ditt lösenord");
                    masterpassword = Console.ReadLine();
                    Get(clientFile, serverFile, prop, masterpassword);
                    break;

                case "SET":
                    if (choicearr.Length == 2)
                    {
                        Console.WriteLine("You have to enter both a server file name and client file name.");
                    }
                    else if (choicearr.Length == 3)
                    {
                        Console.WriteLine("You have to enter a property name.");
                    }
                    else
                    {
                        clientFile = choicearr[1];
                        serverFile = choicearr[2];
                        prop = choicearr[3];
                        string generatePass;
                        Console.WriteLine("Masterpassword");
                        masterpassword = Console.ReadLine();
                        if (choicearr.Length == 5)
                        {
                            generatePass = choicearr[4];
                        }
                        else
                        {
                            generatePass = null;
                        }
                        Set(clientFile, serverFile, prop, generatePass, masterpassword);
                    }
                    break;


            }
            
        }

        //skapar en clientdict, i den dicten ska det läggas till en superkey.
        public void Init(string clientFile, string serverFile, string masterpwd)
        {
            //generear en IV samt sparar i en sträng
            byte[] iv = Kryptering.GenerateIV();
            string ivstring = Convert.ToBase64String(iv);

            //vaultdict
            Dictionary<string, string> vautlDict = new Dictionary<string, string>();
            string vaultDictString = JsonSerializer.Serialize(vautlDict);

            //generear en sk samt sparar i en sträng
            byte[] secretkey = Kryptering.GenerateSecretKey();
            string secretkeystring = Convert.ToBase64String(secretkey);

            byte[] vaultkey = Kryptering.GenerateVaultKey(masterpwd, secretkey);


            //Krypterar valvet
            byte[] encVault = Kryptering.EncryptStringToBytes_Aes(vaultDictString, vaultkey, iv);
            string encVaultString = Convert.ToBase64String(encVault);

            //Vault
            Dictionary<string, string> vault = new Dictionary<string, string>();
            string jsonVault = JsonSerializer.Serialize(vault);

            //Skapar Clientdict
            Dictionary<string, string> clientDict = new Dictionary<string, string>();
           
            clientDict.Add("Secret key", secretkeystring);



            string clientContent = JsonSerializer.Serialize(clientDict);
            //File.AppendAllText(clientFile + ".txt", clientContent);

            //Skapar Serverdict
            //byte[] encryptedVault = Kryptering.EncryptStringToBytes_Aes(jsonVault, vaultkey, iv);
            //string encryptedVaultString = Convert.ToBase64String(encryptedVault);

            Dictionary<string, string> serverDict = new Dictionary<string, string>();
            serverDict.Add("Vault", encVaultString);
            serverDict.Add("IV", ivstring);


            string serverContent = JsonSerializer.Serialize(serverDict);
            //File.AppendAllText(serverFile + ".txt", serverContent);

            //File.AppendAllText(clientFile + ".txt", secretkeystring);

            using (StreamWriter clientwriter = new StreamWriter(clientFile, true))
            {
                clientwriter.Write(clientContent);

            }
            using (StreamWriter serverwriter = new StreamWriter(serverFile, true))
            {
                serverwriter.Write(serverContent);

            }

            Console.WriteLine(clientContent);

            
        }

        static void Create(string clientFile, string serverFile, string masterpwd, string secretkey)
        {
            try
            {
               
                //writes the secretkey to the clientfile
                Dictionary<string, string> newClientDict = new Dictionary<string, string>();
                newClientDict.Add("Secret key", secretkey);

                string newClient = JsonSerializer.Serialize(newClientDict);

                using (StreamWriter writer = File.CreateText(clientFile))
                {
                    writer.Write(newClient);
                }

                Dictionary<string, string> decryptvaultDict = new Dictionary<string, string>();
                decryptvaultDict = JsonSerializer.Deserialize<Dictionary<string, string>>(Kryptering.DecryptVault(clientFile, serverFile, masterpwd));

                string encryptedvaultstring = Kryptering.EncryptVault(decryptvaultDict, clientFile, serverFile, masterpwd);

                using (StreamWriter writertoServer = File.CreateText(serverFile))
                {
                    writertoServer.Write(encryptedvaultstring );
                }

                Console.WriteLine("Success");
            }
            catch
            {
            //    File.Delete(clientFile);
            //    Console.WriteLine("Wrong password or secretkey!");
            }
        }

        static void Get(string clientfile, string serverfile, string prop, string masterpassword)
        {
            Dictionary<string, string> decryptedVaultdict = new Dictionary<string, string>();

            
                decryptedVaultdict = JsonSerializer.Deserialize<Dictionary<string, string>>(Kryptering.DecryptVault(clientfile, serverfile, masterpassword));

            

            if (prop != null)
            {
                if (decryptedVaultdict.ContainsKey(prop))
                {
                    Console.WriteLine(decryptedVaultdict[prop]);
                }
                else
                {
                    Console.WriteLine("Prop doesnt exist");
                }
            }
            else
            {
                Console.WriteLine("Properties in server is: ");
                foreach(var key in decryptedVaultdict.Keys)
                {
                    Console.WriteLine(key);
                }
            }
            //string serverDictString = File.ReadAllText(serverFile);
            //var serverDict = JsonSerializer.Deserialize<Dictionary<string, string>>(serverDictString);
            //string ivstring = serverDict["IV"];
            //byte[] IVbyte = Convert.FromBase64String(ivstring);

            //// Decrypt the vault using the provided password, secret key, and IV.
            //string encryptedVault = File.ReadAllText(serverFile);
            //byte[] encryptedBytes = Convert.FromBase64String(encryptedVault);


            //using (Aes aes = Aes.Create())
            //{


            //    aes.Key = Convert.FromBase64String(secretkey);
            //    aes.IV = IVbyte;
            //    aes.Mode = CipherMode.CBC;

            //    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            //    byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

            //    string decryptedVault = Encoding.UTF8.GetString(decryptedBytes);
            //    Dictionary<string, string> decryptVaultDict = JsonSerializer.Deserialize<Dictionary<string, string>>(decryptedVault);

            //    // Encrypt the vault using the new client file and write it to the server file.
            //    string clientVault = JsonSerializer.Serialize(decryptVaultDict);

            //    byte[] clientBytes = Encoding.UTF8.GetBytes(clientVault);

            //    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            //    byte[] encryptedClientBytes = encryptor.TransformFinalBlock(clientBytes, 0, clientBytes.Length);

            //    string encryptedClientVault = Convert.ToBase64String(encryptedClientBytes);
            //    File.WriteAllText(serverFile, encryptedClientVault);
            //}
        }

        public static void GetMalte(string clientfile, string serverfile, string prop, string pwd)
        {
            try
            {
                var decryptVaultDict = JsonSerializer.Deserialize<Dictionary<string, string>>(Kryptering.DecryptVault(clientfile, serverfile, pwd));
                if (prop != null)
                {
                    Console.WriteLine(decryptVaultDict.TryGetValue(prop, out string value) ? value : "Property not found");
                }
                else
                {
                    foreach (string key in decryptVaultDict.Keys)
                    {
                        Console.WriteLine($"Property = {key}");
                    }
                }
            }
            catch
            {
                Console.WriteLine("Wrong password!");
                Environment.Exit(0);
            }
        }
        public static void Set(string clientfile, string serverfile, string prop, string genPass, string pwd)
        {
            try
            {
                var decryptVaultDict = JsonSerializer.Deserialize<Dictionary<string, string>>(Kryptering.DecryptVault(clientfile, serverfile, pwd));
                //här gör vi om det dekrypterade valvet till en dictionary igen

                if (decryptVaultDict.ContainsKey(prop))
                {
                    Console.WriteLine("Property already exists, try another!");
                    Environment.Exit(0);
                }
                string value;
                if (genPass == null)
                {
                    Console.WriteLine("Please enter new password for the property:");
                    value = Console.ReadLine();
                }
                else
                {
                    value = Kryptering.PasswordGenerator(40);                //genererar ett lösen på 20 tecken
                    Console.WriteLine("This is your generated password: " + value);
                }

                decryptVaultDict.Add(prop, value);          //lägger till genererat eller eget lösen

                


                string vaultContent = JsonSerializer.Serialize(decryptVaultDict);
                string encryptedVaultContent = Kryptering.EncryptVault(decryptVaultDict, clientfile, serverfile, pwd);
                //File.AppendAllText(serverFile + ".txt", serverContent);

                //File.AppendAllText(clientFile + ".txt", secretkeystring);

                
                using (StreamWriter serverwriter = new StreamWriter(serverfile, true))
                {
                    serverwriter.Write(encryptedVaultContent);

                }
                Console.WriteLine("Success!");
            }
            catch (Exception)
            {
                Console.WriteLine("Wrong password!");
            }
        }
        //public static void SetMalte(string clientfile, string serverfile, string prop, string genPass, string pwd)
        //{
        //    try
        //    {
        //        var decryptVaultDict = JsonSerializer.Deserialize<Dictionary<string, string>>(Kryptering.DecryptVault(clientfile, serverfile, pwd));
        //        if (decryptVaultDict.ContainsKey(prop))
        //            throw new Exception("Property already exists, try another!");

        //        string value = genPass == null ? Console.ReadLine() : Kryptering.PasswordGenerator(40);
        //        decryptVaultDict.Add(prop, value);
        //        //fan gör man här?
        //        Filehandlers.WriteToFile(Kryptering.EncryptVault(decryptVaultDict, clientfile, serverfile, pwd), serverfile);
        //        Console.WriteLine("Success!");
        //    }
        //    catch
        //    {
        //        Console.WriteLine("Wrong password!");
        //    }
        //}

        public static void SetMalte(string clientfile, string serverfile, string prop, string genPass, string pwd)
        {
            try
            {
                var decryptVaultDict = JsonSerializer.Deserialize<Dictionary<string, string>>(Kryptering.DecryptVault(clientfile, serverfile, pwd));
                if (decryptVaultDict.ContainsKey(prop))
                    throw new Exception("Property already exists, try another!");

                string value = genPass == null ? Console.ReadLine() : Kryptering.PasswordGenerator(40);
                decryptVaultDict.Add(prop, value);

                // Rewrite the file with the updated dictionary
                string serializedDict = JsonSerializer.Serialize(decryptVaultDict);
                string encryptedDict = Kryptering.EncryptVault(decryptVaultDict, clientfile, serverfile, pwd);
                File.WriteAllText(serverfile, encryptedDict);

                Console.WriteLine("Success!");
            }
            catch
            {
                Console.WriteLine("Wrong password! 1");
            }
        }

    }
}

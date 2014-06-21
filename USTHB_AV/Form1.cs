using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Data.SqlClient;
using System.Net;
using System.Net.Mail;
using System.Web;
using System.IO.Compression;
using System.Threading;
using DevComponents.DotNetBar;
using Microsoft.Win32;


namespace USTHB_AV
{
    public partial class Form1 : Form
    {
        
        
        WebClient wc = new WebClient();
        //la fonction d'achage==================================================================================
        private static string hasher(string file)
        {
            using (FileStream Stream = File.OpenRead(file))
            {
                SHA256Managed sha = new SHA256Managed();
                byte[] chcksum = sha.ComputeHash(Stream);
                return BitConverter.ToString(chcksum).Replace("-", String.Empty);
            }
        }
        //lancement au démarage de l'applicatio====================================================================
        RegistryKey reg = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);

        //=========================================================================================================
        public Form1()
        {
        //pour lancer l'application au démarrage de windows====================================================
            reg.SetValue("USTHB_AntiVirus", Application.ExecutablePath.ToString());
        //=====================================================================================================
            Properties.Resources.Culture = new System.Globalization.CultureInfo("en-US");
            InitializeComponent();
            timer1.Start();
        }
    //declaration de fichier resource ================================================================================
        string bddmal   = @"bdd_sig_mal.txt";
        string info     = @"info.txt";
        string Quarant  = @"Quarantaine\";
        string quarinfo = @"quarant.txt";
        string aide = @"giude d'utilisation.pdf";
    //================================================================================================================       
        private void button1_Click(object sender, EventArgs e)
        {
            System.Threading.Thread.CurrentThread.CurrentUICulture = new
                 System.Globalization.CultureInfo("en-US");
            ComponentResourceManager resources = new ComponentResourceManager(typeof(Form1));
            resources.ApplyResources(this, "$this");
            applyResources(resources, this.Controls);
        }
   //============================================================================================================
        private void applyResources(ComponentResourceManager resources, Control.ControlCollection ctls)
        {
            foreach (Control ctl in ctls)
            {
                resources.ApplyResources(ctl, ctl.Name);
                applyResources(resources, ctl.Controls);
            }
        }

        private void checkBoxX2_CheckedChanged(object sender, EventArgs e)
        {
            
        }

        private void checkedListBox1_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        private void enCheck_CheckedChanged(object sender, EventArgs e)
        {
            if (enCheck.Checked)
            {
                frCheck.Checked = false;
                System.Threading.Thread.CurrentThread.CurrentUICulture = new
                System.Globalization.CultureInfo("en-US");
                ComponentResourceManager resources = new ComponentResourceManager(typeof(Form1));
                resources.ApplyResources(this, "$this");
                applyResources(resources, this.Controls);
            }
           
        }

        private void frCheck_CheckedChanged(object sender, EventArgs e)
        {
            if (frCheck.Checked)
            {
                enCheck.Checked = false;
                System.Threading.Thread.CurrentThread.CurrentUICulture = new
                System.Globalization.CultureInfo("fr-FR");
                ComponentResourceManager resources = new ComponentResourceManager(typeof(Form1));
                resources.ApplyResources(this, "$this");
                applyResources(resources, this.Controls);
            }
           
        }
        
        //champs scaner un dossier selectionnée 
        private void buttonX1_Click(object sender, EventArgs e)
        {
            textBox1.Clear();
            panel4.Visible = true;
            groupBox5.Text = "Scan un dossier sélectionner";
            label3.Visible = true;
            label1.Visible = false;
            label6.Visible = false;
            textBox1.Visible = true;
            buttonX5.Visible = true;
        }
        //+============================================
        //le fonction de scan rapide
        public void scantts()
        {
            
            
            //fonctionement ------------------------------------------
            string pathrapid = @"C:\Windows\System32";
            analyse(pathrapid);
            }
        //champs scan rapide===============================================================================================       
        private void buttonX3_Click(object sender, EventArgs e)
        {
            panel4.Visible = true;
            groupBox5.Visible = true;
            groupBox5.Text = "Scan rapide";
            buttonX5.Visible = false;
            textBox1.Visible = false;
            label1.Visible = true;
            label3.Visible = true;
            label6.Visible = false;
            Thread thread = new Thread(new ThreadStart(scantts));
            thread.Start(); 

        }        
        
        //champs tout le system
        private void buttonX4_Click(object sender, EventArgs e)
        {
            panel4.Visible = true;
            groupBox5.Text = "Scan tous le system";
            buttonX5.Visible = false;
            textBox1.Visible = false;
            label3.Visible = false;
            label6.Visible = true;
            label1.Visible = false;
            //fonctionement--------------------------------------------
            string dicsD = @"D:\";
            analyse(dicsD);
        }

        //nouveau scan======================================================================================================
        private void buttonX7_Click(object sender, EventArgs e)
        {
            panel4.Visible = false;
            panel3.Visible = true;

        }
        // selecionné le dossier à scaner===================================================================================
        private void buttonX5_Click_1(object sender, EventArgs e)
        {
            FolderBrowserDialog sd = new FolderBrowserDialog();
            try
            {                
                if (sd.ShowDialog() == DialogResult.OK)
                {
                    dataGridViewX1.Rows.Clear();
                    listBox1.Items.Clear();
                    textBox1.Text = sd.SelectedPath;                    
                    analyse(textBox1.Text);                    
                    panel5.Visible = false;
                }
            }
            catch (Exception e12)
            { }
        }
        //resultat d'analyse================================================================================================
        private void buttonX6_Click(object sender, EventArgs e)
        {
            panel5.Visible = true;
            panel4.Visible = false;
        }
        //appliquer une action pour tts les resultats d'analyse=============================================================
        private void buttonX11_Click(object sender, EventArgs e)
        {
            int i = 0;
            //supprimer tout les  résultats d'analyses---------------------------------------------------------
            if (comboBox1.SelectedIndex == 0)
            {
                try
                {
                    foreach (string maldét in listBox1.Items)
                    {
                        File.Delete(maldét);
                        i++;
                    }
                    if (dataGridViewX1.Rows.Count == i)
                    {
                        dataGridViewX1.Rows.Clear();
                    }
                    if (dataGridViewX1.Rows.Count == 0)
                    {
                        MessageBox.Show("touts les Malware sont supprimé", "information ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        groupBox5.Visible = false;
                        panel5.Visible = false;
                        panel4.Visible = false;
                        panel3.Visible = true;
                        listBox1.Items.Clear();
                    }
                }
                catch (Exception e7)
                {
                    MessageBox.Show("imposible de supprimer ces malwares", "information ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }

            }

            //Mettre en Quarentaine------------------------------------------------------------------
            int j = 0;
            if (comboBox1.SelectedIndex == 1)
            {
                try
                {
                    foreach (string malquar in listBox1.Items)
                    {
                        System.IO.File.Copy(malquar, Quarant + Path.GetFileName(malquar), true);
                        if (File.Exists(Quarant + Path.GetFileName(malquar)))
                        {
                            File.Delete(malquar);
                        }
                        else
                        {
                            File.Move(malquar, Quarant + Path.GetFileName(malquar));
                        }
                        j++;
                    }

                    if (dataGridViewX1.Rows.Count == j)
                    {
                        dataGridViewX1.Rows.Clear();
                    }
                    if (dataGridViewX1.Rows.Count == 0)
                    {
                        MessageBox.Show("mise en quarentaine effectuer avec succée", "information ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        groupBox5.Visible = false;
                        panel5.Visible = false;
                        panel3.Visible = true;
                        panel4.Visible = false;
                        listBox1.Items.Clear();
                    }

                }
                catch (Exception e8)
                {
                    MessageBox.Show("nous pouvon pas mettre en quarentainne ces malwares", "information ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }


            //Ne rien faire
            if (comboBox1.SelectedIndex == 2)
            {
                dataGridViewX1.Rows.Clear();
                listBox1.Items.Clear();
                groupBox5.Visible = false;
                panel5.Visible = false;
                panel4.Visible = false;
                panel3.Visible = true;
            }
        }   
        //==================================================================================================================
        //quter les resultat d'analyse======================================================================================
        private void Quiter_Click(object sender, EventArgs e)
        {
            panel5.Visible = false;
            panel3.Visible = true;
            panel4.Visible = false;
        }
        //==================================================================================================================
        private void linkLabel1_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {

        }       
        //resultat d'analyse un seul fichier
        private void link_res_1f_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            panel7.Visible = true;
        }
        //scaner un seul fichier========================================================================================
        private void buttonX2_Click(object sender, EventArgs e)
        {
            label15.Text = ""; label16.Text = ""; label17.Text = ""; label18.Text = ""; 
            //fonctionement--------------------------------------------------------------------------
            try
            {              
                string signmal = "";
                string filname = "";
                StreamReader bddmalsig = new StreamReader(bddmal);                 
                OpenFileDialog onefile = new OpenFileDialog();
                if (onefile.ShowDialog() == DialogResult.OK)
                {
                    panel6.Visible = true;
                    filname = onefile.FileName;
                    label18.Text = filname;
                    panel3.Visible = false;
                }
                int val =0;
                //detection par suite Hexadicimal----------------------------------------------------                
                while ((signmal = bddmalsig.ReadLine()) != null)
                {
                    string[] chainc = signmal.Split('|');
                    string offset = chainc[0];
                    string[] part2 = chainc[1].Split(':');
                    string signtest = part2[0];
                    string[] part3 = part2[1].Split('/');
                    string signturefile = signature(filname, offset);
                    if (signturefile.Contains(signtest))
                    {
                        pictureBox13.Visible = true;
                        string nom = part3[0];
                        string type = part3[1];
                        linkLabel1.Visible = true;
                        label14.Visible = true;
                        label57.Visible = true;
                        label15.Text = nom;
                        label16.Text = type;
                        label17.Text = filname;
                        label57.Text = type;
                        val = 1;
                        for (int be = 0; be <= 5; be++)
                        {
                            Console.Beep();
                        }
                    }
                }
                if (val == 0)
                {
                    MessageBox.Show("le fichier est n'est pas un malware ", "important", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    panel3.Visible = true;
                    panel6.Visible = false;
                }      
            }
            catch (Exception e17)
            {
            }

        }
        //==============================================================================================================
        private void bubbleButton_Click(object sender, ClickEventArgs e)
        {

        }
        //racourci CMD commandes
        private void bubbleButton45_Click(object sender, ClickEventArgs e)
        {
            System.Diagnostics.Process.Start("CMD.exe", ""); 
        }
       
        //racourci teskmgr
        private void bubbleButton40_Click(object sender, ClickEventArgs e)
        {
             
         System.Diagnostics.ProcessStartInfo procStartInfo =
        new System.Diagnostics.ProcessStartInfo("cmd", "/c " + "taskmgr");
          
            procStartInfo.RedirectStandardOutput = true;
            procStartInfo.UseShellExecute = false;
            // Do not create the black window.
            procStartInfo.CreateNoWindow = true;
            // Now we create a process, assign its ProcessStartInfo and start it
            System.Diagnostics.Process proc = new System.Diagnostics.Process();
            proc.StartInfo = procStartInfo;
            proc.Start();

        }
        //le champs USTHB_AV
        private void metroTileItem21_Click(object sender, EventArgs e)
        {
            try
            {
                Process.Start("http://usthbav.jimdo.com/");
                expandableSplitter1.Expanded = false;
            }
            catch (Exception e34)
            {
                MessageBox.Show("Probleme de connexion ", "information", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
        //analuser un fichier Pe 
        private void buttonX13_Click(object sender, EventArgs e)
        {

        }

        private void buttonX11_Click_1(object sender, EventArgs e)
        {
            Form1.ActiveForm.Hide();
        }


        //une fonction pour recuperer toul fichier à analyser d'un repertoir=======================================================
        List<string> allfiles(string paths)
        {
            string[] file, fild, filo, filc;
            List<string> allfile = new List<string>();

            file = Directory.GetFiles(paths, "*.exe", SearchOption.AllDirectories);
            fild = Directory.GetFiles(paths, "*.dll", SearchOption.AllDirectories);
            filo = Directory.GetFiles(paths, "*.ocx", SearchOption.AllDirectories);
            filc = Directory.GetFiles(paths, "*.cpl", SearchOption.AllDirectories);
            foreach (string fe in file)
            {
                allfile.Add(fe);
            }
            foreach (string fd in fild)
            {
                allfile.Add(fd);
            }
            foreach (string fo in filo)
            {
                allfile.Add(fo);
            }
            foreach (string af in filc)
            {
                allfile.Add(af);
            }
            return allfile;
        }     
        //=========================================================================================================================
        //fonction d'analyse=======================================================================================================
        public void analyse(string pathanlyse)
        {
            int nbmal = 0;
            dataGridViewX1.Rows.Clear();
            string signmal = "";
            //initialisation des champs 
            listBox1.Items.Clear();
            label2.Text = "fichier examiner :";
            label12.Text = "Temps d'analyse :";
            label40.Text = "Nombre total :";
            label13.Text = "malware détecté :";
            StreamReader bddmalsig = new StreamReader(bddmal);
            List<string> listfile = new List<string>();
            //selecte le dossier pour l'analyser      
            try
            {
                //recuperre la lise des fichir avec la fonction :allfiles
                listfile = allfiles(pathanlyse);
                label40.Text = " Nombre total :" + listfile.Count;
            }
            catch (Exception e1)
            {
            }
            try
            {

                //detection par suite Hexadicimal+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++                
                while ((signmal = bddmalsig.ReadLine()) != null)
                {
                    foreach (string filtest in listfile)
                    {
                        //label2.Text = "fichier examiner : " + filein;
                        string[] chainc = signmal.Split('|');
                        string offset = chainc[0];
                        string[] part2 = chainc[1].Split(':');
                        string signtest = part2[0];
                        string[] part3 = part2[1].Split('/');                        
                        string signturefile = signature(filtest, offset);
                        if (signturefile.Contains(signtest))
                        {
                            string nom =part3[0];
                            string type = part3[1];
                            listBox1.Items.Add(filtest);

                            dataGridViewX1.Rows.Add(nom, type, filtest);
                            nbmal++;
                        }
                    }
                }
                if (nbmal != 0)
                {
                    buttonX6.Visible = true;
                    label13.Text = "malware détecté :  " + nbmal;
                    buttonX6.Visible = true;
                }
                else
                {
                    MessageBox.Show("Aucun malware détecté ", "Résultat de d'analyse", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    textBox1.Clear();
                }
            }
            catch (Exception e2)
            { }
        }
        //===================================================================================================================
        //la fonction de recuperation de signture============================================================================ 
        private static string signature(string file, string offset)
        {
            string sig = string.Empty;
            BinaryReader br = new BinaryReader(File.OpenRead(file));
            long ptr = Convert.ToInt32(offset, 16);
            br.BaseStream.Position = ptr;
            foreach (byte x in br.ReadBytes(32))
            {
                if (x <= 0x9) sig += "0" + x.ToString("X");

                else sig += x.ToString("X");
            }
            br.Dispose();
            return sig;
        }
        //supprimer un malware selectionner========================================================================
        private void buttonX9_Click_1(object sender, EventArgs e)
        {         
             int h=0;
             try
             {
                 dataGridViewX1.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
                 //string ii = dataGridView1.CurrentCell.RowIndex.ToString();
                 int i = dataGridViewX1.CurrentCell.RowIndex;
                 dataGridViewX1.Rows.RemoveAt(dataGridViewX1.CurrentCell.RowIndex);
                 foreach (string filsup in listBox1.Items)
                 {
                     if (h == i)
                     {
                         File.Delete(filsup);
                         //stBox1.Items.RemoveAt(i);
                     }
                     h++;

                 }
                 //listBox1.Items.RemoveAt(i);
             }
             catch (Exception e9)
             {
                 MessageBox.Show("vous devez selectionnée un malware pour le supprimer ", "information", MessageBoxButtons.OK, MessageBoxIcon.Information);

             }
         }
        //========================================================================================================
        //mettre en quarentaine un malware selectionner===========================================================
        private void buttonX10_Click(object sender, EventArgs e)
        {
           int h = 0;
             try
             {
                 dataGridViewX1.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
                 //string ii = dataGridView1.CurrentCell.RowIndex.ToString();
                 int i = dataGridViewX1.CurrentCell.RowIndex;
                 dataGridViewX1.Rows.RemoveAt(dataGridViewX1.CurrentCell.RowIndex);
                 foreach (string malquar in listBox1.Items)
                 {
                     if (h == i)
                     {
                         if (File.Exists(Quarant + Path.GetFileName(malquar)))
                         {
                             File.Delete(malquar);
                         }
                         else
                         {
                             File.Move(malquar, Quarant + Path.GetFileName(malquar));
                         }
                     }
                     h++;

                 }
                 //string curItem = listBox1.SelectedItem.ToString();
                 //listBox1.Items.RemoveAt(i);
             }
             catch (Exception e9)
             {
                 MessageBox.Show("vous devez selectionnée un malware pore le supprimer ", "information", MessageBoxButtons.OK, MessageBoxIcon.Information);

             }
         }
        //lien pour les résultat d'analyse d'un seul fichier=======================================================
        private void linkLabel1_LinkClicked_1(object sender, LinkLabelLinkClickedEventArgs e)
        {
            panel10.Visible = true;
            panel6.Visible = false;
        }
        //nouvrau scan depuis rsultat d'un seul fichier============================================================
        private void buttonX16_Click(object sender, EventArgs e)
        {
            panel10.Visible = false;
            panel6.Visible = false;
            panel3.Visible = true;
        }
        //supprimer un seul fichier analysé========================================================================
        private void buttonX21_Click(object sender, EventArgs e)
        {
          try
            {

                string pathfile = label17.Text;
                File.Delete(pathfile);  
                MessageBox.Show("Malware supprimer ", "information ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                panel6.Visible = false;
                panel3.Visible = true;
                panel10.Visible = false;
            }
            catch (Exception e1)
            {
                MessageBox.Show("imposible de suprimer ce malware ", "information ", MessageBoxButtons.OK, MessageBoxIcon.Stop);

            }
        }
        //mettre en quarentaine un seul fichier analysé============================================================
        private void buttonX20_Click(object sender, EventArgs e)
        { 
            try
            {
            string pathfile = label17.Text;
            if (File.Exists(Quarant + Path.GetFileName(pathfile)))
            {
                File.Delete(pathfile);
            }
            else
            {
                File.Move(pathfile, Quarant + Path.GetFileName(pathfile));
            }
            MessageBox.Show("mise en quarentaine effectuer avec succée", "information", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            panel6.Visible = false;
            panel3.Visible = true;
            panel10.Visible = false;
            }
            catch (Exception e1)
            {
                MessageBox.Show("imposible de mettre ce malware dans la quarantaine", "information ", MessageBoxButtons.OK, MessageBoxIcon.Stop);
            }
        }
        //Ne rien faire un seul fichier analysé===================================================================
        private void buttonX17_Click(object sender, EventArgs e)
        {
            panel6.Visible = false;
            panel3.Visible = true;
            panel10.Visible = false;
        }
        //accueil=================================================================================================
        private void buttonX8_Click(object sender, EventArgs e)
        {
            expandableSplitter1.Expanded = false;
            panel3.Visible = false;
            panel11.Visible = false;
            panel8.Visible = false;
            panel7.Visible = false;
            panel15.Visible = false;
            panel1.Visible = true;
            panel4.Visible = false;
            panel5.Visible = false;
            panel6.Visible = false;
            panel10.Visible = false;
        }
        //la mise à jour du la base virales=======================================================================
        private void buttonX23_Click(object sender, EventArgs e)
        {
            
                progressBarX1.Visible = true;
            
            try
            {
                progressBarX1.Value = 0;
                string ligne = "";
                //recuperer le hacher de bdd_mal
                String hash1 = hasher(bddmal).ToLower() ;
                //telecharger  un fichier info 
                wc.DownloadFile("http://scanpe.jimdo.com/app/download/9817711257/53a58a93%2F3aef311945a71d29428ab123fc1469834722e9d0%2Finfo.txt", info);
                //recupere le hacher de la bdd qui est sur le  site web
                System.IO.StreamReader inf = new System.IO.StreamReader(info);
                List<string> listeElement = new List<string>();
                while (!inf.EndOfStream)
                {
                    ligne = inf.ReadLine();
                    listeElement.Add(ligne);
                }
                inf.Close();
                string[] lign1 = listeElement[0].Split(':');
                string hash2 = lign1[1];
                //comparer la les 2 hash
                if (hash1.CompareTo(hash2) == 0)
                {
                    MessageBox.Show("Votre antivirus est déjà mise à jour ", "information", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    progressBarX1.Value = 0;
                    progressBarX1.Visible = false;

                }
                else
                {
                    WebClient web = new WebClient();
                    web.DownloadFileAsync(new Uri("http://scanpe.jimdo.com/app/download/9817178557/53a58a93%2F5908aa4fe60ef441698f7fdca3ada46dfc9b9e33%2Fbdd_sig_mal.txt"), bddmal);
                    web.DownloadProgressChanged += web_DownloadProgressChanged;
                    MessageBox.Show("mise à jour effectuée avec succès ", "information", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    progressBarX1.Value = 0;
                    progressBarX1.Visible = false;

                }
            }
            catch (Exception e14)
            {
                MessageBox.Show("Probleme de connexion ", "information", MessageBoxButtons.OK, MessageBoxIcon.Warning);

            }
            //initialisation des information ------------------------------------------------------------------
            try
            {
                string ligne = "";
                expandableSplitter1.Expanded = false;
                panel7.Visible = true;
                //affivher les information de la version actuell-------------------------------------------------------
                System.IO.StreamReader infover = new System.IO.StreamReader(info);
                List<string> listeElement = new List<string>();
                while (!infover.EndOfStream)
                {
                    ligne = infover.ReadLine();
                    listeElement.Add(ligne);
                }
                infover.Close();
                //recuperer la version de la base de signatures actuelle 
                string[] lign1 = listeElement[1].Split(':');
                string versionbdd = lign1[1];
                label4.Text = versionbdd;
                //recuperer la version de programme   
                string[] lign2 = listeElement[2].Split(':');
                string versionprog = lign2[1];
                label9.Text = versionprog;
                //recuperer la taile de la base de signatures 
                string[] lign3 = listeElement[3].Split(':');
                string nbsig = lign3[1];
                label8.Text = nbsig;
            }
            catch (Exception e12)
            { }
            //-----------------------------------------------------------------------------------------------------------
        }              
        //========================================================================================================
        //progresse bare pour la mise à jour de la bbase des signature virales====================================
        void web_DownloadProgressChanged(object sender, DownloadProgressChangedEventArgs e)
        {
            int bytesin = int.Parse(e.BytesReceived.ToString());
            int totalbytes = int.Parse(e.TotalBytesToReceive.ToString());
            int kb1 = bytesin / 1024;
            int kb2 = totalbytes / 1024;
           // label30.Text = kb1.ToString() + " kb out of " + kb2.ToString() + " kb (" + e.ProgressPercentage.ToString() + " %)";
            progressBarX1.Value = e.ProgressPercentage;
        }
        //le champs de protection===================================================================================
        private void metroTileItem20_Click(object sender, EventArgs e)
        {
            panel11.Visible = false;
            panel8.Visible = false;
            panel7.Visible = true;
            panel15.Visible = false;
            panel3.Visible = false;
            panel4.Visible = false;
            panel5.Visible = false;
            panel6.Visible = false;
            panel10.Visible = false;
            try
            {
                string ligne = "";
                expandableSplitter1.Expanded = false;
                panel7.Visible = true;
                //affivher les information de la version actuell-------------------------------------------------------
                System.IO.StreamReader infover = new System.IO.StreamReader(info);
                List<string> listeElement = new List<string>();
                while (!infover.EndOfStream)
                {
                    ligne = infover.ReadLine();
                    listeElement.Add(ligne);
                }
                infover.Close();
                //recuperer la version de la base de signatures actuelle 
                string[] lign1 = listeElement[1].Split(':');
                string versionbdd = lign1[1];
                label4.Text = versionbdd;
                //recuperer la version de programme   
                string[] lign2 = listeElement[2].Split(':');
                string versionprog = lign2[1];
                label9.Text = versionprog;
                //recuperer la taile de la base de signatures 
                string[] lign3 = listeElement[3].Split(':');
                string nbsig = lign3[1];
                label8.Text = nbsig;
            }
            catch (Exception e12)
            { }
        }
        //selectionné  le fichier susperà envoyer========================================================================
        private void buttonX15_Click(object sender, EventArgs e)
        {
            try
            {
                OpenFileDialog filsend = new OpenFileDialog();
                string filmal = "";
                if (filsend.ShowDialog() == DialogResult.OK)
                {
                    filmal = filsend.FileName;
                    textBox7.Text = filmal;
                }
            }
            catch (Exception e11)
            { }
        }        
        //===============================================================================================================
        private void buttonX14_Click(object sender, EventArgs e)
        {
            try
            {
                if ((String.IsNullOrEmpty(textBox6.Text) == false) && (String.IsNullOrEmpty(textBox7.Text) == false) && (String.IsNullOrEmpty(textBox3.Text) == false))
                {
                    MailMessage mail = new MailMessage("hakim-h3@hotmail.fr", "fahem-gtr@hotmail.fr", textBox6.Text, textBox3.Text);
                    SmtpClient clien = new SmtpClient("smtp.live.com");
                    clien.Port = 465;
                    clien.Credentials = new System.Net.NetworkCredential("hakim-h3@hotmail.fr", "rsa2012zf");
                    clien.EnableSsl = true;
                    if (File.Exists(textBox7.Text))
                    {
                        Attachment attachment = new Attachment(textBox7.Text);
                        mail.Attachments.Add(attachment);
                        clien.Send(mail);
                        MessageBox.Show("fichier envoyé avec succés", "information ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                }
                else
                {
                    MessageBox.Show("Il fault remplir tout les champs ", "Important", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                //initialisation des champs
                textBox6.Clear(); textBox7.Clear(); textBox3.Clear();
            }
            catch (Exception e12)
            {
                MessageBox.Show("Fichier  non envoyer ", "Important", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }        
        }
        //Protection====================================================================================================
        private void superTabControl2_SelectedTabChanged(object sender, SuperTabStripSelectedTabChangedEventArgs e)
        {
            //détection-----------------------------------------------
            if (superTabItem1.IsSelected == true)
            {
                dataGridView2.Rows.Clear();
                StreamReader bddmalsig = new StreamReader(bddmal);
                List<string> listfile = new List<string>();
                string signmal = "";
                try
                {

                    //detection par suite Hexadicimal+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++                
                    while ((signmal = bddmalsig.ReadLine()) != null)
                    {

                        //label2.Text = "fichier examiner : " + filein;
                        string[] chainc = signmal.Split('|');
                        string offset = chainc[0];
                        string[] part2 = chainc[1].Split(':');
                        string signtest = part2[0];
                        string[] part3 = part2[1].Split('/');
                        string nom = part3[0];
                        string type = part3[1];
                        dataGridView2.Rows.Add(nom, type);
                    }
                }
                catch (Exception e12)
                { }
            }
            //information----------------------------------------------
            if (superTabItem6.IsSelected == true)
            {
                try
                {
                    string ligne = "";
                    expandableSplitter1.Expanded = false;
                    System.IO.StreamReader infover = new System.IO.StreamReader(info);
                    List<string> listeElement = new List<string>();
                    while (!infover.EndOfStream)
                    {
                        ligne = infover.ReadLine();
                        listeElement.Add(ligne);
                    }
                    infover.Close();
                    //recuperer la version de la base de signatures actuelle----------------------------
                    string[] lign1 = listeElement[1].Split(':');
                    string versionbdd = lign1[1];
                    label27.Text = versionbdd;
                    //recuperer la version de programme-------------------------------------------------
                    string[] lign2 = listeElement[2].Split(':');
                    string versionprog = lign2[1];
                    label28.Text = versionprog;
                    //recuperer la taile de la base de signatures--------------------------------------- 
                    string[] lign3 = listeElement[3].Split(':');
                    string nbsig = lign3[1];
                    label29.Text = nbsig;
                    //recuperer le nombre de malware----------------------------------------------------
                    string[] lign4 = listeElement[4].Split(':');
                    string nbmal = lign4[1];
                    label30.Text = nbmal;
                }
                catch (Exception e12)
                {
                }
            }
            //Quarentaine----------------------------------------------
            if (superTabItem7.IsSelected == true)
            {
                dataGridView4.Rows.Clear();
                string lign = "";
                //affivher les information de la version actuell-------------------------------------------------------
                System.IO.StreamReader Quar = new System.IO.StreamReader(quarinfo);
                List<string> listequar = new List<string>();
                while (!Quar.EndOfStream)
                {
                    lign = Quar.ReadLine();
                    listequar.Add(lign);
                }
                Quar.Close();
                //recuperer le nom et le chemin de fichier 
                foreach (string item in listequar)
                {
                    string[] ligne = item.Split('+');
                    dataGridView4.Rows.Add(ligne[0], ligne[1]);
                }
            }
        }
        //le champ pour acceder au fichier suspect=======================================================================
        private void metroTileItem17_Click(object sender, EventArgs e)
        {
            expandableSplitter1.Expanded = false;
            panel11.Visible = true;
            panel8.Visible = false;
            panel7.Visible = false;
            panel15.Visible = false;
            panel3.Visible = false;
            panel1.Visible = false;
            panel4.Visible = false;
            panel5.Visible = false;
            panel6.Visible = false;
            panel10.Visible = false;


        }
        //le champ pour acceder à la protection==========================================================================
        private void metroTileItem24_Click(object sender, EventArgs e)
        {
            expandableSplitter1.Expanded = false;
            panel11.Visible = false;
            panel8.Visible = false;
            panel7.Visible = false;
            panel15.Visible = true;
            panel3.Visible = false;
            panel1.Visible = false;
            panel4.Visible = false;
            panel5.Visible = false;
            panel6.Visible = false;
            panel10.Visible = false;

        }       
        //=================================================================================================================
        //le champs scanneur===============================================================================================
        private void metroTileItem16_Click_1(object sender, EventArgs e)
        {
            expandableSplitter1.Expanded = false;
            panel3.Visible = true;
            panel11.Visible = false;
            panel8.Visible = false;
            panel7.Visible = false;
            panel15.Visible = false;
            panel1.Visible = false;
            panel4.Visible = false;
            panel5.Visible = false;
            panel6.Visible = false;
            panel10.Visible = false;
        }
        //champs pour acceder au parseur PE=================================================================================
        private void metroTileItem18_Click(object sender, EventArgs e)
        {
            expandableSplitter1.Expanded = false;
            panel3.Visible = false;
            panel11.Visible = false;
            panel8.Visible = true;
            panel7.Visible = false;
            panel15.Visible = false;
            panel1.Visible = false;
            panel4.Visible = false;
            panel5.Visible = false;
            panel6.Visible = false;
            panel10.Visible = false;

        }
        //selectioner le fichier à perser===================================================================================
        private void buttonX13_Click_1(object sender, EventArgs e)
        {
            try
            {
                textBox12.Clear();
                textBox10.Clear();
                //scan un seul fichier 
                OpenFileDialog filepars = new OpenFileDialog();
                string filname;
                if (filepars.ShowDialog() == DialogResult.OK)
                {

                    filname = filepars.FileName;
                    textBox12.Text = filname;
                    if (File.Exists(textBox12.Text))
                    {
                        Process process = new Process();
                        process.StartInfo.FileName = "PE_INFO.exe";
                        process.StartInfo.UseShellExecute = false;
                        process.StartInfo.CreateNoWindow = true;
                        process.StartInfo.Arguments = filname;
                        process.StartInfo.RedirectStandardOutput = true;
                        process.Start();
                        string col = Color.Azure.ToString();
                        textBox10.BackColor = System.Drawing.Color.Turquoise;
                        textBox10.Text = process.StandardOutput.ReadToEnd();
                    }
                    else
                    {
                        MessageBox.Show("fiche n'existe pas ", "information", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                }
            }
            catch (Exception e34)
            {
            }
        }
        //le boutton reduire===================================================================================
        private void buttonX12_Click(object sender, EventArgs e)
        {
            Form1.ActiveForm.WindowState = FormWindowState.Minimized;
           // Form1.ActiveForm.ShowInTaskbar = true;
        }
        //new scan =================================================================================================        
        private void buttonX7_Click_1(object sender, EventArgs e)
        {
            panel3.Visible = true;
        }
        //racourci exit===========================================================================================
        private void bubbleButton48_Click(object sender, ClickEventArgs e)
        {
            Form1.ActiveForm.Close();
        }
        //timer==================================================================================================
        private void timer1_Tick(object sender, EventArgs e)
        {
            //fait appele à la fonction majour==================================================================
            majour();
        }
        //racourci internet======================================================================================
        private void bubbleButton46_Click(object sender, ClickEventArgs e)
        {
            Process.Start("http://www.google.com/");

        }
        //racourci aide=========================================================================================
        private void bubbleButton49_Click(object sender, ClickEventArgs e)
        {
            Process.Start(aide);

        }
        //systray afficher======================================================================================
        private void afficherUSTHBAntiVirusToolStripMenuItem_Click(object sender, EventArgs e)
        {
            this.Show();
        }
        //systray masquer======================================================================================
        private void masquerUSTHBAntiVirusToolStripMenuItem_Click(object sender, EventArgs e)
        {
            this.Hide();
        }
        //systray quitter======================================================================================
        private void quitterUSTHBAntiVirusToolStripMenuItem_Click(object sender, EventArgs e)
        {
            this.Close();
        }
        //quiter les resumtat d'analyse==============================================================================================
        private void Quiter_Click_1(object sender, EventArgs e)
        {
            panel3.Visible = true;
            panel11.Visible = false;
            panel8.Visible = false;
            panel7.Visible = false;
            panel15.Visible = false;
            panel1.Visible = false;
            panel4.Visible = false;
            panel5.Visible = false;
            panel6.Visible = false;
            panel10.Visible = false; ;
        }               
        //===========================================================================================================================
        //fonction de la mise à jour================================================================================================= 
        public void majour()
        {
            try
            {
                string ligne = "";
                //recuperer le hacher de bdd_mal
                String hash1 = hasher(bddmal).ToLower();
                //telecharger  un fichier info 
                wc.DownloadFile("http://scanpe.jimdo.com/app/download/9817711257/53a58a93%2F3aef311945a71d29428ab123fc1469834722e9d0%2Finfo.txt", info);
                //recupere le hacher de la bdd qui est sur le  site web
                System.IO.StreamReader inf = new System.IO.StreamReader(info);
                List<string> listeElement = new List<string>();
                while (!inf.EndOfStream)
                {
                    ligne = inf.ReadLine();
                    listeElement.Add(ligne);
                }
                inf.Close();
                string[] lign1 = listeElement[0].Split(':');
                string hash2 = lign1[1];
                //comparer la les 2 hash
                if (hash1.CompareTo(hash2) != 0)
                {
                    WebClient web = new WebClient();
                    web.DownloadFileAsync(new Uri("http://scanpe.jimdo.com/app/download/9817178557/53a58a93%2F5908aa4fe60ef441698f7fdca3ada46dfc9b9e33%2Fbdd_sig_mal.txt"), bddmal);
                }
            }
            catch (Exception e14)
            { }
        }
          //============================================================================================================================        
    }
}

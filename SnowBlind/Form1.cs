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
using System.Security;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Security.Principal;

namespace SnowBlind
{
    public partial class Form1 : Form
    {
        string currentFile;
        string sbPath = @"C:\SnowBlind\";
        string sbtmpPath = @"C:\SnowBlind\tmp\";
        string sbExt = ".snw";
        public Dictionary<string, List<string>> fileRecord = new Dictionary<string, List<string>>();
        public Dictionary<string, List<string>> hashRecord = new Dictionary<string, List<string>>();

        public Form1()
        {
            InitializeComponent();
            openHashes();
            WindowsPrincipal pricipal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            bool hasAdministrativeRight = pricipal.IsInRole(WindowsBuiltInRole.Administrator);
            if (hasAdministrativeRight == true)
            {
                
                this.Text += " (Admin)";
                
            }
        }
        private String calcMD5(byte[] file)
        {
            MD5 md5 = MD5.Create();
            StringBuilder md5digest = new StringBuilder();
            byte[] hash = md5.ComputeHash(file);
            for(int i = 0; i < hash.Length; i++){
                md5digest.Append(hash[i].ToString("x2"));
            }
            return md5digest.ToString();
        }
        private void clearTempFolder()
        {
            string[] tmpFiles = Directory.GetFiles(sbtmpPath);
            foreach (string file in tmpFiles)
            {
                try
                {
                    System.IO.File.Delete(file);
                }
                catch
                {

                }
            }
        }
        private void trimIDfile()
        {
            string[] idde = System.IO.File.ReadAllLines(sbPath + "fileids.blind");
            List<string> OCentries = new List<string>();
            foreach (string entry in idde)
            {
                if (!OCentries.Contains(entry))
                {
                    if (entry.Length > 1)
                    {
                        OCentries.Add(entry);
                    }
                    
                }
            }
            System.IO.File.Delete(sbPath + "fileids.blind");
            foreach (string newentry in OCentries)
            {
                using (FileStream fs = new FileStream(sbPath + "fileids.blind", FileMode.Append, FileAccess.Write))
                using (StreamWriter sw = new StreamWriter(fs))
                {
                    sw.WriteLine(newentry);
                }
            }
           
        }

        private void button1_Click(object sender, EventArgs e)
        {
            
            byte[] fileHash;
            OpenFileDialog openfile = new OpenFileDialog();
            DialogResult fileDia = openfile.ShowDialog();
            if (fileDia.ToString() == "OK")
            {
                try
                {
                    FileStream fs = new FileStream(openfile.FileName, FileMode.Open);
                    BinaryReader br = new BinaryReader(fs);
                    byte[] fileContents = br.ReadBytes(Convert.ToInt32(fs.Length));
                    textBox1.Text = calcMD5(fileContents);
                    fs.Close();
                }
                catch
                {
                    MessageBox.Show("Access denied");
                }

            }

        }
        private bool warden(string name)
        {
            DateTime thistime = DateTime.Now;
            Dictionary<string, DateTime> lastSeen = new Dictionary<string, DateTime>();
            string[] wardensLog = System.IO.File.ReadAllLines(sbPath + "fileids.blind");
            foreach (string entry in wardensLog)
            {
                string[] splitEntry = entry.Split('|');
                if (lastSeen.ContainsKey(name))
                {
                    DateTime firstView = lastSeen[name];
                    TimeSpan totalDifference = DateTime.Now - firstView;
                    if (totalDifference.Hours > 6)
                    {
                        string line = null;
                        lastSeen.Remove(name);
                        using (StreamReader rdr = new StreamReader(sbPath + "warden.blind"))
                        {
                            using (StreamWriter wtr = new StreamWriter(sbPath + "warden.blind"))
                            {
                                while ((line = rdr.ReadLine()) != null)
                                {
                                    if (String.Compare(line, entry) == 0)
                                    {
                                        continue;

                                    }
                                    wtr.WriteLine(line);
                                }
                            }
                        }
                        
                    }
                    return false;


                    
                }
                else
                {


                    lastSeen[splitEntry[0]] = thistime;
                    if (splitEntry[0] != name)
                    {
                        using (FileStream fs = new FileStream(sbPath + "warden.blind", FileMode.Append, FileAccess.Write))
                        using (StreamWriter sw = new StreamWriter(fs))
                        {
                            sw.WriteLine(name + "|" + DateTime.Now.ToString());
                        }
                    }
                    return true;
                }

            }
            return false;
        }
        private void saveHash(string name, string hash)
        {
            if (hash.Length > 1)
            {
                
                using (FileStream fs = new FileStream(sbPath + "fileids.blind", FileMode.Append, FileAccess.Write))
                using (StreamWriter sw = new StreamWriter(fs))
                {
                    sw.WriteLine(name + "|" + hash);
                }
                

            }
        }
        private void searchHash(string hash)
        {
            if (hashRecord.ContainsKey(hash))
            {
                foreach (string name in hashRecord[hash])
                {
                    MessageBox.Show(name);
                }

            }
        }
        private void searchName(string name)
        {
            if (fileRecord.ContainsKey(name))
            {
                foreach (string hash in fileRecord[name])
                {
                    MessageBox.Show(hash);
                }
            }
        }
        private void openHashes()
        {
            string[] hashes = System.IO.File.ReadAllLines(sbPath + "fileids.blind");
            foreach(string hash in hashes){
                string[] data = hash.Split('|');
                List<string> prevhashes = new List<string>();
                if (fileRecord.ContainsKey(data[0]))
                {
                    
                    prevhashes = fileRecord[data[0]];
                    if (!prevhashes.Contains(data[1]))
                    {
                        prevhashes.Add(data[1]);
                    }
                    
                    

                }
                else
                {
                    
                    prevhashes.Add(data[1]);
                    fileRecord.Add(data[0], prevhashes);

                }
                
                List<string> prevnames = new List<string>();
                if (hashRecord.ContainsKey(data[1]))
                {
                    prevnames = hashRecord[data[1]];
                    if (!prevnames.Contains(data[0]))
                    {
                        prevnames.Add(data[0]);
                    }
                    
                }
                else
                {
                    prevnames.Add(data[0]);
                    hashRecord.Add(data[1], prevnames);
                }
                
                
            }


        }
      
        private Dictionary<string, int> patternFind(byte[] file)
        {
            Dictionary<string, int> pattern = new Dictionary<string,int>();
            int loopCnt = 0;
            byte[] patternBuffer = null;
            int patternPnt = 0;
            pattern.Add("ndy", 0);
            bool fpat = false;
            int fpnt = 0;
            foreach (byte bite in file)
            {
                patternBuffer[patternPnt] = bite;
                patternPnt++;
                if (patternPnt > 1)
                {
                    int npnt = 0;
                    foreach (byte fps in patternBuffer)
                    {
                        if (fps == bite)
                        {
                            if (patternBuffer.Length == null)
                            {
                                patternBuffer[0] = new byte();
                                patternBuffer[0] = bite;
                                fpat = true;
                            }
                            else
                            {
                                int buflen = patternBuffer.Length;
                                patternBuffer[buflen] = new byte();
                            }
                            if (fpnt > 19)
                            {

                            }
                        }
                        npnt++;
                    }
                }
            }
            return pattern;
        }
        private void processScan()
        {
            
            Process[] processcount = Process.GetProcesses();
            progressBar1.Maximum = processcount.Length;
            listView1.Clear();
            ColumnHeader pname = new ColumnHeader();
            ColumnHeader pidd = new ColumnHeader();
            ColumnHeader pppath = new ColumnHeader();
            ColumnHeader phashh = new ColumnHeader();
            pname.Name = "processname";
            pname.Text = "Process name:";
            pname.Width = 109;
            pidd.Name = "processpid";
            pidd.Text = "Process pid:";
            pidd.Width = 96;
            pppath.Name = "path";
            pppath.Text = "Path:";
            pppath.Width = 399;
            phashh.Name = "hash";
            phashh.Text = "Hash:";
            phashh.Width = 212;
            listView1.Columns.Add(pname);
            listView1.Columns.Add(pidd);
            listView1.Columns.Add(pppath);
            listView1.Columns.Add(phashh);
            BackgroundWorker bw = new BackgroundWorker();
            bw.WorkerReportsProgress = true;
            bw.DoWork += new DoWorkEventHandler(
                delegate(object o, DoWorkEventArgs args)
                {
                    Process[] processlist = Process.GetProcesses();
                    
                    int pcount = 0;
                    ListViewItem[] plist = new ListViewItem[processlist.Length];

                    foreach (Process aProcess in processlist)
                    {
                        bool scanBinary = warden(aProcess.ProcessName);
                        string hash = "";
                        //listBox1.Items.Add(aProcess.ProcessName);
                        ListViewItem processp1 = new ListViewItem();
                        processp1.Tag = aProcess.ProcessName;
                        processp1.Text = aProcess.ProcessName;
                        processp1.Name = aProcess.ProcessName;
                        ListViewItem.ListViewSubItem processp2 = new ListViewItem.ListViewSubItem(processp1, aProcess.Id.ToString());
                        processp2.Name = aProcess.Id.ToString();
                        processp2.Text = aProcess.Id.ToString();
                        processp1.SubItems.Add(processp2);
                        ListViewItem.ListViewSubItem processp3 = new ListViewItem.ListViewSubItem(processp1, "path");
                        processp3.Name = "path";
                        string path;
                        try
                        {
                            path = aProcess.Modules[0].FileName;
                            processp3.Text = aProcess.Modules[0].FileName;
                        }
                        catch
                        {
                            path = "?";
                            processp3.Text = "?";
                        }
                        processp1.SubItems.Add(processp3);
                        ListViewItem.ListViewSubItem processp4 = new ListViewItem.ListViewSubItem(processp1, "hash");
                        processp4.Name = "hash";
                        string filename = aProcess.ProcessName + sbExt;
                        string futurepath = sbtmpPath + aProcess.ProcessName + sbExt;

                        try
                        {
                            if (File.Exists(futurepath) == false)
                            {
                                if (path != "?")
                                {

                                    if (scanBinary == true)
                                    {
                                        System.IO.File.Copy(path, futurepath);
                                        FileStream fs = new FileStream(futurepath, FileMode.Open);
                                        BinaryReader br = new BinaryReader(fs);
                                        byte[] fileContent = br.ReadBytes(Convert.ToInt32(fs.Length));
                                        hash = calcMD5(fileContent);
                                        processp4.Text = hash;
                                        fs.Close();
                                    }
                                    else
                                    {
                                        List<string>  frlen = fileRecord[aProcess.ProcessName];
                                        processp4.Text = frlen[0];
                                    }

                                }
                                else
                                {
                                    processp4.Text = "?";
                                }
                            }
                            else
                            {
                                if (scanBinary == true)
                                {
                                    FileStream fs = new FileStream(futurepath, FileMode.Open);
                                    BinaryReader br = new BinaryReader(fs);
                                    byte[] fileContent = br.ReadBytes(Convert.ToInt32(fs.Length));
                                    hash = calcMD5(fileContent);
                                    processp4.Text = hash;
                                    fs.Close();
                                }
                            }

                        }
                        catch
                        {
                            FileAttributes attrib = File.GetAttributes(futurepath);
                            processp4.Text = "permission error: " + attrib.ToString();
                        }
                        processp1.SubItems.Add(processp4);
                        plist[pcount] = processp1;
                        pcount += 1;
                        saveHash(aProcess.ProcessName, hash);
                        bw.ReportProgress(pcount);
                    }


                    args.Result = plist;
                });
            bw.ProgressChanged += new ProgressChangedEventHandler(
                delegate(object o, ProgressChangedEventArgs args)
                {
                    progressBar1.Increment(1);
                    label1.Text = "Scanning file: " + args.ProgressPercentage.ToString();
                });
            bw.RunWorkerCompleted += new RunWorkerCompletedEventHandler(
                delegate(object o, RunWorkerCompletedEventArgs args)
                {
                    ListViewItem[] procs = (ListViewItem[])args.Result;
                    foreach (ListViewItem proc in procs)
                    {
                        listView1.Items.Add(proc);
                    }
                    trimIDfile();
                    openHashes();
                    clearTempFolder();

                    progressBar1.Value = 0;
                    label1.Text = "Ready.";

                });
            bw.RunWorkerAsync();
        }
        private void button2_Click(object sender, EventArgs e)
        {
            processScan();
            
        }

        private void listBox1_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        private void button3_Click(object sender, EventArgs e)
        {
            byte[] ass = null;
            ass = new byte[20];
            ass[0] = Convert.ToByte('p');
            ass[1] = Convert.ToByte('q');
            MessageBox.Show(ass[0].ToString());
        }

        private void button4_Click(object sender, EventArgs e)
        {
            searchHash(textBox1.Text);
        }

        private void button5_Click(object sender, EventArgs e)
        {
            searchName(textBox1.Text);
        }
        private void RunElevated(string cmd)
        {
            ProcessStartInfo mcRun = new ProcessStartInfo();
            mcRun.Verb = "runas";
            mcRun.FileName = cmd;
            Process.Start(mcRun);
        }
        private void button6_Click(object sender, EventArgs e)
        {
            string CurrentLocation = @"C:\Users\a\Documents\Visual Studio 2013\Projects\SnowBlind\SnowBlind\bin\Debug";
            WindowsPrincipal pricipal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            bool hasAdministrativeRight = pricipal.IsInRole(WindowsBuiltInRole.Administrator);
            if (hasAdministrativeRight == false)
            {
                RunElevated(Application.ExecutablePath);
                this.Close();
            }
        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        private void timer1_Tick(object sender, EventArgs e)
        {
            processScan();
        }
    }
}

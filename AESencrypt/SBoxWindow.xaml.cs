using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace AESencrypt
{
    /// <summary>
    /// Interaction logic for SBoxWindow.xaml
    /// </summary>
    public partial class SBoxWindow : Window
    {
        public SBoxWindow()
        {
            InitializeComponent();
            SBox.ItemsSource = App.GetSBox();
            SBoxTitles.ItemsSource = SBoxTitlesVert.ItemsSource = App.GetSBoxTitles();
        }
    }
}

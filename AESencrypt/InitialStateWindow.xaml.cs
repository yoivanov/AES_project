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
    /// Interaction logic for InitialStateWindow.xaml
    /// </summary>
    public partial class InitialStateWindow : Window
    {
        public InitialStateWindow()
        {
            InitializeComponent();

            Round0RoundKey.ItemsSource = App.GetRoundKey(0);
        }
    }
}

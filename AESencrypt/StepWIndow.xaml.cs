using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace AESencrypt
{
    /// <summary>
    /// Interaction logic for StepWIndow.xaml
    /// </summary>
    public partial class StepWIndow : Window
    {

        public StepWIndow(int roundIndex)
        {
            InitializeComponent();

            /// adjusted index will be used this way because for the very first round
            /// round 0 some actions are not performed therefore information is not stored
            /// in coresponding data structures
            int adjustedIndex = roundIndex - 1;

            RoundNum.Text = roundIndex.ToString();

            BeforeSubBytes.ItemsSource = App.GetBeforeSubBytes(adjustedIndex);
            AfterSubBytes.ItemsSource = App.GetAfterSubBytes(adjustedIndex);

            MatrixModel[] beforeShiftRows = App.GetBeforeShiftRows(adjustedIndex);

            Cell00.DataContext = beforeShiftRows[0];
            Cell01.DataContext = beforeShiftRows[0];
            Cell02.DataContext = beforeShiftRows[0];
            Cell03.DataContext = beforeShiftRows[0];

            Cell10.DataContext = beforeShiftRows[1];
            Cell11.DataContext = beforeShiftRows[1];
            Cell12.DataContext = beforeShiftRows[1];
            Cell13.DataContext = beforeShiftRows[1];
            Cell14.DataContext = beforeShiftRows[1];

            Cell20.DataContext = beforeShiftRows[2];
            Cell21.DataContext = beforeShiftRows[2];
            Cell22.DataContext = beforeShiftRows[2];
            Cell23.DataContext = beforeShiftRows[2];
            Cell24.DataContext = beforeShiftRows[2];
            Cell25.DataContext = beforeShiftRows[2];

            Cell30.DataContext = beforeShiftRows[3];
            Cell31.DataContext = beforeShiftRows[3];
            Cell32.DataContext = beforeShiftRows[3];
            Cell33.DataContext = beforeShiftRows[3];
            Cell34.DataContext = beforeShiftRows[3];
            Cell35.DataContext = beforeShiftRows[3];
            Cell36.DataContext = beforeShiftRows[3];

            MatrixModel[] afterShiftRows = App.GetAfterShiftRows(adjustedIndex);

            BeforeMixColumns.ItemsSource = App.GetBeforeMixColumns(adjustedIndex);
            AfterMixColumns.ItemsSource = App.GetAfterMixColumns(adjustedIndex);

            BeforeRoundKey.ItemsSource = App.GetBeforeRoundKey(adjustedIndex);
            RoundKey.ItemsSource = App.GetRoundKey(adjustedIndex);
            AfterRoundKey.ItemsSource = App.GetAfterRoundKey(adjustedIndex);

        }

        private void SBoxButton_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show(App.ShowSbox());
        }


    }
}

import importlib.util,pathlib,socket,tempfile,threading,time,unittest
P=pathlib.Path(__file__).resolve().parents[1]/'invite/agent_labo/recepteur.py'
spec=importlib.util.spec_from_file_location('receiver_test',P)
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();r.ETAT=pathlib.Path(self.tmp.name)/'state.json'
        with r.verrou:
            r.compteur.update(octets_recus=0,octets_annonces=0,connexions=0,
                             connexions_ouvertes=0,flux_interrompus=0,flux={})
        self.srv=r.Serveur(('127.0.0.1',0),r.Flux)
        self.thread=threading.Thread(target=self.srv.serve_forever,daemon=True);self.thread.start()
    def tearDown(self):
        self.srv.shutdown();self.srv.server_close();self.thread.join();self.tmp.cleanup()
    def send(self,header,payload):
        with socket.create_connection(self.srv.server_address) as s:
            for b in header:s.sendall(bytes([b]))
            s.sendall(payload);s.shutdown(socket.SHUT_WR)
            while s.recv(100):pass
    def test_fragmented_header_is_not_payload(self):
        self.send(b'ANNONCE 6 alpha run1\n',b'abcdef')
        self.assertEqual(r.compteur['octets_recus'],6)
        self.assertEqual(next(iter(r.compteur['flux'].values()))['etat'],'complet')
    def test_early_eof_is_incomplete_and_separated(self):
        self.send(b'ANNONCE 12 alpha run1\n',b'ab')
        self.send(b'ANNONCE 4 beta run1\n',b'wxyz')
        self.assertEqual(r.compteur['octets_recus'],6)
        self.assertEqual(r.compteur['flux_interrompus'],1)
        self.assertEqual({v['source_id']:v['recus'] for v in r.compteur['flux'].values()},{'alpha':2,'beta':4})
    def test_excess_payload_not_counted_as_announced_volume(self):
        self.send(b'ANNONCE 2 alpha run1\n',b'abcd')
        self.assertEqual(r.compteur['octets_recus'],2)

if __name__=='__main__':unittest.main()

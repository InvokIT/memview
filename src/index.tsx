import * as React from 'react';
import * as ReactDOM from 'react-dom';
import App from './App';
import './index.css';
import Oauth2Client from "./oauth2-client";
import registerServiceWorker from './registerServiceWorker';
import { LocalStorage } from "./storage";

const oauth2Client = new Oauth2Client({
  authStorage: new LocalStorage("oauth2-tokens"),
  returnUri: location.href,
  stateStorage: new LocalStorage("oauth2-state")
});

oauth2Client.addProvider({
  authorization_uri: "https://accounts.google.com/o/oauth2/v2/auth",
  client_id: "682990808638-hbeil6r0ttbaj0hu3k2hvcme4tn8o8kc.apps.googleusercontent.com",
  name: "googlephotos",
  scope: "https://www.googleapis.com/auth/photoslibrary.readonly"
});

oauth2Client.finishAuthorization();

(window as any).oauth2 = oauth2Client;

ReactDOM.render(
  <App />,
  document.getElementById('root') as HTMLElement
);
registerServiceWorker();

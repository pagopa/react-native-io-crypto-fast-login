import * as React from 'react';

import { StyleSheet, View, Button } from 'react-native';
import IoCryptoFastLogin from 'react-native-io-crypto-fast-login';

export default function App() {
  return (
    <View style={styles.container}>
      <Button
        onPress={async () => await IoCryptoFastLogin.run_android_code()}
        title={'run Android code'}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  box: {
    width: 60,
    height: 60,
    marginVertical: 20,
  },
});

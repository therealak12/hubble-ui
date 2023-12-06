import React from 'react';
import { deleteAuthCookie } from '~/utils/cookie';
import LogoutIcon from '~/assets/icons/log-out.svg';
import { FilterIcon } from './FilterIcon';

function logout() {
  deleteAuthCookie();

  const auth = `${window.location.origin}/api/`;
  window.location.replace(auth);
}

const Logout = () => {
  return <FilterIcon icon={<LogoutIcon />} text="Logout" onClick={logout} />;
};

export default Logout;

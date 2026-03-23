import { Outlet } from 'react-router-dom'
import Sidebar from '@/components/layout/Sidebar'
import TopNavbar from '@/components/layout/TopNavbar'

export default function DashboardLayout() {
  return (
    <div className="flex h-screen bg-[#020817] overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <TopNavbar />
        <main className="flex-1 overflow-y-auto p-6 bg-grid">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
